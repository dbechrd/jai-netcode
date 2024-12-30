/*
Native Jai port of Glenn Fiedler's "netcode" C library as of this commit:
https://github.com/mas-bandwidth/netcode/commit/3ffe69ad33416789bfb651bf687fdc619344e261

------------------------------------------------------------------------------------------------------------------------
| Original BSD-3 license
------------------------------------------------------------------------------------------------------------------------
    netcode

    Copyright © 2017 - 2024, Mas Bandwidth LLC

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-----------------------------------------------------------------------------------------------------------------------
*/

#module_parameters () (ENABLE_LOGGING := false);

#load "tests.jai";

NETCODE_CONNECT_TOKEN_BYTES     :: 2048;
NETCODE_KEY_BYTES               :: 32;
NETCODE_MAC_BYTES               :: 16;
NETCODE_USER_DATA_BYTES         :: 256;
NETCODE_MAX_SERVERS_PER_CONNECT :: 32;

NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED         :: -6;
NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN         :: -5;
NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT          :: -4;
NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT :: -3;
NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT  :: -2;
NETCODE_CLIENT_STATE_CONNECTION_DENIED             :: -1;
NETCODE_CLIENT_STATE_DISCONNECTED                  ::  0;
NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST    ::  1;
NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE   ::  2;
NETCODE_CLIENT_STATE_CONNECTED                     ::  3;

NETCODE_MAX_CLIENTS     :: 256;
NETCODE_MAX_PACKET_SIZE :: 1200;

NETCODE_OK    :: 1;
NETCODE_ERROR :: 0;

NETCODE_ADDRESS_NONE :: 0;
NETCODE_ADDRESS_IPV4 :: 1;
NETCODE_ADDRESS_IPV6 :: 2;

EncryptionKeyBuf :: [NETCODE_KEY_BYTES] u8;
ConnectTokenBuf  :: [NETCODE_CONNECT_TOKEN_BYTES] u8;

netcode_init :: () -> int {
    assert(!netcode.initialized);

    if !socket_init() {
        return NETCODE_ERROR;
    }

    // TODO(dlb): We're ignoring Sodium for now.
    // if ( sodium_init() == -1 )
    //     return NETCODE_ERROR;

    netcode.initialized = true;
    return NETCODE_OK;
}

netcode_term :: () {
    assert(netcode.initialized);

    // TODO(dlb): Kill Socket here (though we can't actually do that because
    //            Socket doesn't have a term function that calls WSACleanup).
    #if OS == .WINDOWS {
        WSACleanup();
    }

    netcode.initialized = false;
}

// ----------------------------------------------------------------

netcode_address_t :: struct {
    type: u8;
    port: u16;
    data: union {
        ipv4: [4] u8;
        ipv6: [8] u16;
    }
}

// ----------------------------------------------------------------

netcode_client_config_t :: struct {
    network_simulator             : *netcode_network_simulator_t;
    callback_context              : *void;
    state_change_callback         : (callback_context: *void, old_state: int, new_state: int);
    send_loopback_packet_callback : (callback_context: *void, client_index: int, packet_data: [] u8, sequence: u64);
    override_send_and_receive     : bool;
    send_packet_override          : (callback_context: *void, to: netcode_address_t, packet_data: [] u8);
    receive_packet_override       : (callback_context: *void, from: *netcode_address_t, packet_data: [] u8) -> packet_bytes: int;
}

netcode_client_t :: struct {
    config                   : netcode_client_config_t;
    state                    : int;
    time                     : Apollo_Time;
    connect_start_time       : Apollo_Time;
    last_packet_send_time    : Apollo_Time;
    last_packet_receive_time : Apollo_Time;
    should_disconnect        : bool;
    should_disconnect_state  : int;
    sequence                 : u64;
    client_index             : int;
    max_clients              : int;
    server_address_index     : int;
    address                  : netcode_address_t;
    server_address           : netcode_address_t;
    connect_token            : netcode_connect_token_t;
    socket_holder            : netcode_socket_holder_t;
    ctx                      : netcode_context_t;
    replay_protection        : netcode_replay_protection_t;
    packet_receive_queue     : netcode_packet_queue_t;
    challenge_token_sequence : u64;
    challenge_token_data     : ChallengeTokenBuf;
    receive_packet_data      : [NETCODE_CLIENT_MAX_RECEIVE_PACKETS][] u8;
    receive_from             : [NETCODE_CLIENT_MAX_RECEIVE_PACKETS] netcode_address_t;
    loopback                 : bool;
}

netcode_client_create :: (address: string, config: netcode_client_config_t, time: Apollo_Time) -> *netcode_client_t {
    return netcode_client_create_overload(address, .{}, config, time);
}

netcode_client_destroy :: (using client: *netcode_client_t) {
    assert(client != null);
    if (!loopback) {
        netcode_client_disconnect(client);
    } else {
        netcode_client_disconnect_loopback(client);
    }
    netcode_socket_destroy(*socket_holder.ipv4);
    netcode_socket_destroy(*socket_holder.ipv6);
    netcode_packet_queue_clear(*packet_receive_queue);
    free(client);
}

netcode_client_connect :: (using client: *netcode_client_t, connect_token_buf: ConnectTokenBuf) {
    assert(client != null);
    assert(connect_token_buf.count > 0);

    netcode_client_disconnect(client);

    if netcode_read_connect_token(connect_token_buf, *connect_token) != NETCODE_OK {
        netcode_client_set_state(client, NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN);
        return;
    }

    server_address_index = 0;
    server_address = connect_token.server_addresses[0];

    server_address_string := netcode_address_to_string(server_address,, temp);
    netcode_log(.VERBOSE_ONLY, "client connecting to server % [%/%]\n", server_address_string, server_address_index + 1, connect_token.num_server_addresses);

    ctx.read_packet_key = connect_token.server_to_client_key;
    ctx.write_packet_key = connect_token.client_to_server_key;

    netcode_client_reset_before_next_connect(client);

    netcode_client_set_state(client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST);
}

netcode_client_update :: (using client: *netcode_client_t, _time: Apollo_Time) {
    assert(client != null);

    time = _time;

    if loopback {
        return;
    }

    netcode_client_receive_packets(client);
    netcode_client_send_packets(client);

    if state > NETCODE_CLIENT_STATE_DISCONNECTED && state < NETCODE_CLIENT_STATE_CONNECTED {
        connect_token_expire_duration := (connect_token.expire_timestamp - connect_token.create_timestamp);
        if time - connect_start_time >= connect_token_expire_duration {
            netcode_log(.VERBOSE_ONLY, "client connect failed. connect token expired\n");
            netcode_client_disconnect_internal(client, NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, false);
            return;
        }
    }

    if should_disconnect {
        netcode_log(.VERY_VERBOSE_ONLY, "client should disconnect -> %\n", netcode_client_state_name(should_disconnect_state));
        if netcode_client_connect_to_next_server(client) {
            return;
        }
        netcode_client_disconnect_internal(client, should_disconnect_state, false);
        return;
    }

    timed_out := connect_token.timeout_seconds > .{} && last_packet_receive_time + connect_token.timeout_seconds < time;

    if state == {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST;
            if timed_out {
                netcode_log(.VERBOSE_ONLY, "client connect failed. connection request timed out\n");
                if netcode_client_connect_to_next_server(client) {
                    return;
                }
                netcode_client_disconnect_internal(client, NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT, false);
                return;
            }
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE;
            if timed_out {
                netcode_log(.VERBOSE_ONLY, "client connect failed. connection response timed out\n");
                if netcode_client_connect_to_next_server(client) {
                    return;
                }
                netcode_client_disconnect_internal(client, NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT, false);
                return;
            }
        case NETCODE_CLIENT_STATE_CONNECTED;
            if timed_out {
                netcode_log(.VERBOSE_ONLY, "client connection timed out\n");
                netcode_client_disconnect_internal(client, NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT, false);
                return;
            }
    }
}

netcode_client_next_packet_sequence :: inline (using client: *netcode_client_t) -> u64 {
    assert(client != null);
    return sequence;
}

netcode_client_send_packet :: (using client: *netcode_client_t, packet_data: [] u8) {
    assert(client != null);
    assert(packet_data.count >= 0);
    assert(packet_data.count <= NETCODE_MAX_PACKET_SIZE);

    if state != NETCODE_CLIENT_STATE_CONNECTED {
        return;
    }

    if !loopback {
        packet := netcode_create_payload_packet(packet_data.count,, temp);
        assert(packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);
        packet.payload_data = packet_data;

        netcode_client_send_packet_to_server_internal(client, packet);
    } else {
        assert(config.send_loopback_packet_callback != null);
        config.send_loopback_packet_callback(config.callback_context, client_index, packet_data, sequence);
        sequence += 1;
    }
}

netcode_client_receive_packet :: (using client: *netcode_client_t) -> packet: [] u8, packet_sequence: u64 {
    assert(client != null);

    packet, packet_sequence := netcode_packet_queue_pop(*packet_receive_queue);

    if packet != null {
        assert(packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);
        p := cast(*netcode_connection_payload_packet_t) packet;

        assert(p.payload_data.count >= 0);
        assert(p.payload_data.count <= NETCODE_MAX_PAYLOAD_BYTES);
        return p.payload_data, packet_sequence;
    } else {
        return .{}, 0;
    }
}

// TODO(dlb)[cleanup]: We don't really need this weird overload. Call netcode_free_payload_packet directly.
netcode_client_free_packet :: (client: *netcode_client_t, packet: [] u8) {
    netcode_free_payload_packet(packet);
}

netcode_client_disconnect :: (using client: *netcode_client_t) {
    assert(client != null);
    assert(!loopback);
    netcode_client_disconnect_internal(client, NETCODE_CLIENT_STATE_DISCONNECTED, true);
}

netcode_client_state :: inline (using client: *netcode_client_t) -> int {
    assert(client != null);
    return state;
}

netcode_client_index :: inline (using client: *netcode_client_t) -> int {
    assert(client != null);
    return client_index;
}

netcode_client_max_clients :: inline (using client: *netcode_client_t) -> int {
    assert(client != null);
    return max_clients;
}

netcode_client_connect_loopback :: (using client: *netcode_client_t, _client_index: int, _max_clients: int) {
    assert(client != null);
    assert(state <= NETCODE_CLIENT_STATE_DISCONNECTED);

    netcode_log(.VERBOSE_ONLY, "client connected to server via loopback as client %\n", client_index);
    state = NETCODE_CLIENT_STATE_CONNECTED;
    client_index = _client_index;
    max_clients = _max_clients;
    loopback = true;
}

netcode_client_disconnect_loopback :: (using client: *netcode_client_t) {
    assert(client != null);
    assert(loopback);

    netcode_client_reset_connection_data(client, NETCODE_CLIENT_STATE_DISCONNECTED);
}

netcode_client_process_packet :: (client: *netcode_client_t, from: *netcode_address_t, packet_buf: [] u8) {
    allowed_packets: AllowedPacketsBuf;
    allowed_packets[NETCODE_CONNECTION_DENIED_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_CHALLENGE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = true;

    current_timestamp = current_time_monotonic();
    packet, packet_sequence := netcode_read_packet(
        packet_buf,
        client.ctx.read_packet_key,
        client.connect_token.protocol_id,
        current_timestamp,
        .{},
        allowed_packets,
        *client.replay_protection,
    );

    if (!packet)
        return;

    netcode_client_process_packet_internal(client, from, packet, packet_sequence);
}

netcode_client_loopback :: (using client: *netcode_client_t) -> bool {
    assert(client != null);
    return loopback;
}

netcode_client_process_loopback_packet :: (using client: *netcode_client_t, packet_data: [] u8, packet_sequence: u64) {
    assert(client != null);
    assert(loopback);

    packet := netcode_create_payload_packet(packet_data.count);
    if packet == null {
        return;
    }
    memcpy(packet.payload_data.data, packet_data.data, packet_data.count);

    netcode_log(.VERY_VERBOSE_ONLY, "client processing loopback packet from server\n");
    netcode_packet_queue_push(*packet_receive_queue, packet, packet_sequence);
}

netcode_client_get_port :: (using client: *netcode_client_t) -> u16 {
    assert(client != null);
    return ifx address.type == NETCODE_ADDRESS_IPV4 then socket_holder.ipv4.address.port else socket_holder.ipv6.address.port;
}

netcode_client_server_address :: (using client: *netcode_client_t) -> netcode_address_t {
    assert(client != null);
    return server_address;
}

netcode_generate_connect_token :: (
    public_server_addresses   : [] string,
    internal_server_addresses : [] string,
    expire_seconds            : Apollo_Time,
    timeout_seconds           : Apollo_Time,
    client_id                 : u64,
    protocol_id               : u64,
    private_key               : EncryptionKeyBuf,
    user_data                 : UserDataBuf,
    output_buffer             : ConnectTokenBuf
) -> int {
    assert(public_server_addresses.count > 0);
    assert(public_server_addresses.count <= NETCODE_MAX_SERVERS_PER_CONNECT);
    assert(internal_server_addresses.count == public_server_addresses.count);

    // parse public server addresses

    parsed_public_server_addresses := NewArray(public_server_addresses.count, netcode_address_t,, temp);
    for public_server_addresses {
        if netcode_parse_address(it, *parsed_public_server_addresses[it_index]) != NETCODE_OK {
            return NETCODE_ERROR;
        }
    }

    // parse internal server addresses

    parsed_internal_server_addresses := NewArray(internal_server_addresses.count, netcode_address_t,, temp);
    for internal_server_addresses {
        if netcode_parse_address(it, *parsed_internal_server_addresses[it_index]) != NETCODE_OK {
            return NETCODE_ERROR;
        }
    }

    // generate a connect token

    nonce: BigNonceBuf;
    netcode_generate_nonce(nonce);

    connect_token_private: netcode_connect_token_private_t;
    netcode_generate_connect_token_private(*connect_token_private, client_id, timeout_seconds, parsed_internal_server_addresses, user_data);

    // write it to a buffer

    connect_token_data: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(connect_token_private, connect_token_data);

    // encrypt the buffer

    create_timestamp := current_time_monotonic();
    expire_timestamp := ifx expire_seconds >= .{} then create_timestamp + expire_seconds else create_timestamp + CONNECT_TOKEN_EXPIRE_MAX;
    if netcode_encrypt_connect_token_private(connect_token_data, NETCODE_VERSION_INFO, protocol_id, expire_timestamp, nonce, private_key) != NETCODE_OK {
        return NETCODE_ERROR;
    }

    // wrap a connect token around the private connect token data

    connect_token: netcode_connect_token_t;
    array_copy(connect_token.version_info, NETCODE_VERSION_INFO);
    connect_token.protocol_id = protocol_id;
    connect_token.create_timestamp = create_timestamp;
    connect_token.expire_timestamp = expire_timestamp;
    array_copy(connect_token.nonce, nonce);
    array_copy(connect_token.private_data, connect_token_data);
    connect_token.num_server_addresses = parsed_public_server_addresses.count;
    for parsed_public_server_addresses {
        connect_token.server_addresses[it_index] = it;
    }
    array_copy(connect_token.client_to_server_key, connect_token_private.client_to_server_key);
    array_copy(connect_token.server_to_client_key, connect_token_private.server_to_client_key);
    connect_token.timeout_seconds = timeout_seconds;

    // write the connect token to the output buffer

    netcode_write_connect_token(*connect_token, output_buffer);

    return NETCODE_OK;
}

// ----------------------------------------------------------------

netcode_server_config_t :: struct {
    protocol_id                   : u64;
    private_key                   : EncryptionKeyBuf;
    network_simulator             : *netcode_network_simulator_t;
    callback_context              : *void;
    connect_disconnect_callback   : (callback_context: *void, client_index: int, connected: bool);
    send_loopback_packet_callback : (callback_context: *void, client_index: int, packet_data: [] u8, sequence: u64);
    override_send_and_receive     : int;
    send_packet_override          : (callback_context: *void, to: netcode_address_t, packet_data: [] u8);
    receive_packet_override       : (callback_context: *void, from: *netcode_address_t, packet_data: [] u8) -> packet_bytes: int;
}

netcode_server_t :: struct {
    config                          : netcode_server_config_t;
    socket_holder                   : netcode_socket_holder_t;
    address                         : netcode_address_t;
    flags                           : u32;
    time                            : Apollo_Time;
    running                         : bool;
    max_clients                     : int;
    num_connected_clients           : int;
    global_sequence                 : u64;
    challenge_sequence              : u64;
    challenge_key                   : EncryptionKeyBuf;
    client_connected                : [NETCODE_MAX_CLIENTS] bool;
    client_timeout                  : [NETCODE_MAX_CLIENTS] Apollo_Time;
    client_loopback                 : [NETCODE_MAX_CLIENTS] bool;
    client_confirmed                : [NETCODE_MAX_CLIENTS] bool;
    client_encryption_index         : [NETCODE_MAX_CLIENTS] int;
    client_id                       : [NETCODE_MAX_CLIENTS] u64;
    client_sequence                 : [NETCODE_MAX_CLIENTS] u64;
    client_last_packet_send_time    : [NETCODE_MAX_CLIENTS] Apollo_Time;
    client_last_packet_receive_time : [NETCODE_MAX_CLIENTS] Apollo_Time;
    client_user_data                : [NETCODE_MAX_CLIENTS] UserDataBuf;
    client_replay_protection        : [NETCODE_MAX_CLIENTS] netcode_replay_protection_t;
    client_packet_queue             : [NETCODE_MAX_CLIENTS] netcode_packet_queue_t;
    client_address                  : [NETCODE_MAX_CLIENTS] netcode_address_t;
    client_address_map              : netcode_address_map_t;
    connect_token_entries           : [NETCODE_MAX_CONNECT_TOKEN_ENTRIES] netcode_connect_token_entry_t;
    encryption_manager              : netcode_encryption_manager_t;
    receive_packet_data             : [NETCODE_SERVER_MAX_RECEIVE_PACKETS] [] u8;  // TODO(dlb): Should the slice be MAX_PACKET_BYTES or something?
    //receive_packet_bytes            : [NETCODE_SERVER_MAX_RECEIVE_PACKETS] int;  // TODO(dlb): Use the packet_data slice
    receive_from                    : [NETCODE_SERVER_MAX_RECEIVE_PACKETS] netcode_address_t;
}

netcode_server_create :: (server_address_string: string, config: netcode_server_config_t, time: Apollo_Time) -> *netcode_server_t {
    return netcode_server_create_overload(server_address_string, .{}, config, time);
}

netcode_server_destroy :: (server: *netcode_server_t) {
    assert(server != null);

    netcode_server_stop(server);

    netcode_socket_destroy(*server.socket_holder.ipv4);
    netcode_socket_destroy(*server.socket_holder.ipv6);

    free(server);
}

netcode_server_start :: (using server: *netcode_server_t, _max_clients: int) {
    assert(server != null);
    assert(_max_clients > 0);
    assert(_max_clients <= NETCODE_MAX_CLIENTS);

    if running {
        netcode_server_stop(server);
    }

    netcode_log(.VERBOSE_ONLY, "server started with % client slots\n", _max_clients);

    running = true;
    max_clients = _max_clients;
    num_connected_clients = 0;
    challenge_sequence = 0;
    netcode_generate_key(server.challenge_key);
}

netcode_server_stop :: (using server: *netcode_server_t) {
    assert(server != null);

    if !running {
        return;
    }

    netcode_server_disconnect_all_clients(server);

    running = false;
    max_clients = 0;
    num_connected_clients = 0;

    global_sequence = 0;
    challenge_sequence = 0;
    array_zero(challenge_key);

    netcode_connect_token_entries_reset(connect_token_entries);
    netcode_encryption_manager_reset(*encryption_manager);

    netcode_log(.VERBOSE_ONLY, "server stopped\n");
}

netcode_server_running :: (using server: *netcode_server_t) -> bool {
    assert(server != null);
    return running;
}

netcode_server_max_clients :: (using server: *netcode_server_t) -> int {
    assert(server != null);
    return max_clients;
}

netcode_server_update :: (using server: *netcode_server_t, _time: Apollo_Time) {
    assert(server != null);
    time = _time;
    netcode_server_receive_packets(server);
    netcode_server_send_packets(server);
    netcode_server_check_for_timeouts(server);
}

netcode_server_client_connected :: (using server: netcode_server_t, client_index: int) -> bool {
    if !running {
        return false;
    }
    if client_index < 0 || client_index >= max_clients {
        return false;
    }

    return client_connected[client_index];
}

netcode_server_client_id :: (using server: netcode_server_t, client_index: int) -> u64 {
    if !running {
        return false;
    }
    if client_index < 0 || client_index >= max_clients {
        return false;
    }

    return client_id[client_index];
}

netcode_server_client_address :: (using server: netcode_server_t, client_index: int) -> netcode_address_t {
    if !running {
        return null;
    }
    if client_index < 0 || client_index >= max_clients {
        return null;
    }

    return client_address[client_index];
}

netcode_server_disconnect_client :: (using server: *netcode_server_t, client_index: int) {
    assert(server != null);

    if (!running) {
        return;
    }

    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(client_loopback[client_index] == false);

    if (!client_connected[client_index]) {
        return;
    }
    if (client_loopback[client_index]) {
        return;
    }

    netcode_server_disconnect_client_internal(server, client_index, true);
}

netcode_server_disconnect_all_clients :: (using server: *netcode_server_t) {
    assert(server != null);

    if !running {
        return;
    }

    for 0..max_clients-1 {
        if client_connected[it] && !client_loopback[it] {
            netcode_server_disconnect_client_internal(server, it, true);
        }
    }
}

netcode_server_next_packet_sequence :: (using server: *netcode_server_t, client_index: int) -> u64 {
    assert(client_index >= 0);
    assert(client_index < max_clients);

    if !client_connected[client_index] {
        return 0;
    }

    return client_sequence[client_index];
}

netcode_server_send_packet :: (using server: *netcode_server_t, client_index: int, packet_data: [] u8) {
    assert(server != null);
    assert(packet_data.count >= 0);
    assert(packet_data.count <= NETCODE_MAX_PACKET_SIZE);

    if !running {
        return;
    }

    assert(client_index >= 0);
    assert(client_index < max_clients);

    if !client_connected[client_index] {
        return;
    }

    if !client_loopback[client_index] {
        packet := netcode_create_payload_packet(packet_data.count,, temp);
        assert(packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);
        memcpy(packet.payload_data.data, packet_data.data, packet_data.count);

        if !client_confirmed[client_index] {
            keep_alive_packet: netcode_connection_keep_alive_packet_t;
            assert(keep_alive_packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
            keep_alive_packet.client_index = client_index;
            keep_alive_packet.max_clients = max_clients;
            netcode_server_send_client_packet(server, *keep_alive_packet, client_index);
        }

        netcode_server_send_client_packet(server, packet, client_index);
    } else {
        assert(config.send_loopback_packet_callback != null);
        config.send_loopback_packet_callback(config.callback_context, client_index, packet_data, client_sequence[client_index]);

        client_sequence[client_index] += 1;
        client_last_packet_send_time[client_index] = time;
    }
}

netcode_server_receive_packet :: (using server: *netcode_server_t, client_index: int) -> packet: [] u8, sequence: u64 {
    assert(server != null);

    if !running {
        return .{}, 0;
    }

    if !client_connected[client_index] {
        return .{}, 0;
    }

    assert(client_index >= 0);
    assert(client_index < max_clients);

    packet, sequence := netcode_packet_queue_pop(*client_packet_queue[client_index]);
    if packet == null {
        return .{}, 0;
    }

    assert(packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);
    p := cast(*netcode_connection_payload_packet_t) packet;
    assert(p.payload_data.count >= 0);
    assert(p.payload_data.count <= NETCODE_MAX_PAYLOAD_BYTES);
    return p.payload_data, sequence;
}

// TODO(dlb)[cleanup]: We don't really need this weird overload. Call netcode_free_payload_packet directly.
netcode_server_free_packet :: (server: *netcode_server_t, packet: [] u8) {
    netcode_free_payload_packet(packet);
}

netcode_server_num_connected_clients :: (using server: *netcode_server_t) -> int {
    assert(server != null);
    return num_connected_clients;
}

netcode_server_client_user_data :: (using server: *netcode_server_t, client_index: int) -> UserDataBuf {
    assert(server != null);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    return client_user_data[client_index];
}

netcode_server_process_packet :: (using server: *netcode_server_t, from: netcode_address_t, packet_data: [] u8) {
    if !running {
        return;
    }
    if packet_data.count == 0 {
        return;
    }

    allowed_packets: AllowedPacketsBuf;
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = true;

    current_timestamp := current_time_monotonic();

    encryption_index := -1;
    client_index := netcode_server_find_client_index_by_address(server, from);
    if client_index != -1 {
        assert(client_index >= 0);
        assert(client_index < max_clients);
        encryption_index = client_encryption_index[client_index];
    } else {
        encryption_index = netcode_encryption_manager_find_encryption_mapping(*encryption_manager, from, time);
    }

    read_packet_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);
    if read_packet_key == null && packet_data[0] != 0 {
        netcode_log(.VERY_VERBOSE_ONLY, "server could not process packet (type %) because no encryption mapping exists for %\n", packet_data[0] & 0xF, netcode_address_to_string(from,, temp));
        return;
    }

    packet, sequence := netcode_read_packet(
        packet_data,
        read_packet_key.*,
        config.protocol_id,
        current_timestamp,
        config.private_key,
        allowed_packets,
        ifx client_index != -1 then *client_replay_protection[client_index] else null
    );

    if packet == null {
        return;
    }

    netcode_server_process_packet_internal(server, from, packet, sequence, encryption_index, client_index);
}

netcode_server_connect_loopback_client :: (using server: *netcode_server_t, client_index: int, _client_id: u64, user_data: UserDataBuf) {
    assert(server != null);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(running);
    assert(!client_connected[client_index]);
    assert(num_connected_clients < max_clients);

    client_loopback[client_index] = true;
    client_connected[client_index] = true;
    client_confirmed[client_index] = true;
    client_encryption_index[client_index] = -1;
    client_id[client_index] = _client_id;
    client_sequence[client_index] = 0;
    client_address[client_index] = .{};
    netcode_address_map_set(*client_address_map, client_address[client_index], client_index);
    client_last_packet_send_time[client_index] = time;
    client_last_packet_receive_time[client_index] = time;

    if user_data.count > 0 {
        array_copy(client_user_data[client_index], user_data);
    } else {
        array_zero(client_user_data[client_index]);
    }

    netcode_log(.VERBOSE_ONLY, "server connected loopback client % in slot %\n", _client_id, client_index);
    num_connected_clients += 1;

    if config.connect_disconnect_callback {
        config.connect_disconnect_callback(config.callback_context, client_index, true);
    }
}

netcode_server_disconnect_loopback_client :: (using server: *netcode_server_t, client_index: int) {
    assert(server != null);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(running);
    assert(client_connected[client_index]);
    assert(client_loopback[client_index]);
    assert(num_connected_clients > 0);

    netcode_log(.VERBOSE_ONLY, "server disconnected loopback client %\n", client_index);

    if config.connect_disconnect_callback {
        config.connect_disconnect_callback(config.callback_context, client_index, false);
    }

    while true {
        packet := netcode_packet_queue_pop(*client_packet_queue[client_index]);
        if packet == null {
            break;
        }
        free(packet);
    }

    netcode_packet_queue_clear(*client_packet_queue[client_index]);

    client_connected[client_index] = false;
    client_loopback[client_index] = false;
    client_confirmed[client_index] = false;
    client_id[client_index] = 0;
    client_sequence[client_index] = 0;
    client_last_packet_send_time[client_index] = .{};
    client_last_packet_receive_time[client_index] = .{};
    netcode_address_map_delete(*client_address_map, client_address[client_index]);
    client_address[client_index] = .{};
    client_encryption_index[client_index] = -1;
    array_zero(client_user_data[client_index]);

    num_connected_clients -= 1;
}

netcode_server_client_loopback :: (using server: *netcode_server_t, client_index: int) -> bool {
    assert(server != null);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(running);
    return client_loopback[client_index];
}

netcode_server_process_loopback_packet :: (using server: *netcode_server_t, client_index: int, packet_data: [] u8, packet_sequence: u64) {
    assert(server != null);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(running);
    assert(packet_data.count >= 0);
    assert(packet_data.count <= NETCODE_MAX_PACKET_SIZE);
    assert(client_connected[client_index]);
    assert(client_loopback[client_index]);

    packet := netcode_create_payload_packet(packet_data.count);
    if packet == null {
        return;
    }
    memcpy(packet.payload_data.data, packet_data.data, packet_data.count);

    netcode_log(.VERY_VERBOSE_ONLY, "server processing loopback packet from client %\n", client_index);

    client_last_packet_receive_time[client_index] = time;

    netcode_packet_queue_push(*client_packet_queue[client_index], packet, packet_sequence);
}

netcode_server_get_port :: (using server: *netcode_server_t) -> u16 {
    assert(server != null);
    return ifx address.type == NETCODE_ADDRESS_IPV4 then socket_holder.ipv4.address.port else socket_holder.ipv6.address.port;
}

// ----------------------------------------------------------------

netcode_network_simulator_t :: struct {
    latency_milliseconds        : float;
    jitter_milliseconds         : float;
    packet_loss_percent         : float;
    duplicate_packet_percent    : float;
    time                        : Apollo_Time;
    current_index               : int;
    num_pending_receive_packets : int;
    packet_entries              : [NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES] netcode_network_simulator_packet_entry_t;
    pending_receive_packets     : [NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS] netcode_network_simulator_packet_entry_t;
}

#scope_module

encrypt_security_warning_shown := false;
decrypt_security_warning_shown := false;
fake_mac_security_warning_shown := false;

#import "Basic";
#import "Socket";
#import "Random";
System :: #import "System";
#import "IPAddress";
#import "Trivial";

CONNECT_TOKEN_EXPIRE_MAX :: #run seconds_to_apollo(60 * 60 * 24);  // 24 hours
#assert CONNECT_TOKEN_EXPIRE_MAX > Apollo_Time.{};
#assert APOLLO_TIME_INVALID < Apollo_Time.{};
#assert seconds_to_apollo(-1) < Apollo_Time.{};
#assert seconds_to_apollo(0) == Apollo_Time.{};
#assert seconds_to_apollo(1) > Apollo_Time.{};

NETCODE_SOCKET_IPV6 :: 1;
NETCODE_SOCKET_IPV4 :: 2;

NETCODE_CONNECT_TOKEN_PRIVATE_BYTES   :: 1024;
NETCODE_CONNECT_TOKEN_NONCE_BYTES     :: 24;
NETCODE_CHALLENGE_TOKEN_BYTES         :: 300;
NETCODE_CHALLENGE_TOKEN_NONCE_BYTES   :: 12;
NETCODE_VERSION_INFO_BYTES            :: 13;
NETCODE_MAX_PACKET_BYTES              :: 1300;  // MUST be a multiple of 4, because bit_reader reads 32-bit words at a time
NETCODE_MAX_PAYLOAD_BYTES             :: 1200;
NETCODE_MAX_ADDRESS_STRING_LENGTH     :: 256;
NETCODE_PACKET_QUEUE_SIZE             :: 256;
NETCODE_REPLAY_PROTECTION_BUFFER_SIZE :: 256;
NETCODE_CLIENT_MAX_RECEIVE_PACKETS    :: 64;
NETCODE_SERVER_MAX_RECEIVE_PACKETS    :: 64 * NETCODE_MAX_CLIENTS;
NETCODE_CLIENT_SOCKET_SNDBUF_SIZE     :: 256 * 1024;
NETCODE_CLIENT_SOCKET_RCVBUF_SIZE     :: 256 * 1024;
NETCODE_SERVER_SOCKET_SNDBUF_SIZE     :: 4 * 1024 * 1024;
NETCODE_SERVER_SOCKET_RCVBUF_SIZE     :: 4 * 1024 * 1024;

NETCODE_VERSION_INFO           :: cast(VerionInfoBuf) "NETCODE 1.02\0";
NETCODE_PACKET_SEND_RATE       :: 10;
NETCODE_NUM_DISCONNECT_PACKETS :: 10;

NETCODE_ADDRESS_MAP_BUCKETS :: NETCODE_MAX_CLIENTS;

// ----------------------------------------------------------------

ConnectTokenPrivateDataBuf :: [NETCODE_CONNECT_TOKEN_PRIVATE_BYTES] u8;
BigNonceBuf                :: [NETCODE_CONNECT_TOKEN_NONCE_BYTES] u8;    // use big nonce for when you don't have a sequential number (random bytes; bigger to reduce collisions)
ChallengeTokenBuf          :: [NETCODE_CHALLENGE_TOKEN_BYTES] u8;
NonceBuf                   :: [NETCODE_CHALLENGE_TOKEN_NONCE_BYTES] u8;  // use regular nonce when you have a sequential number
VerionInfoBuf              :: [NETCODE_VERSION_INFO_BYTES] u8;
UserDataBuf                :: [NETCODE_USER_DATA_BYTES] u8;
MacBuf                     :: [NETCODE_MAC_BYTES] u8;
AllowedPacketsBuf          :: [NETCODE_CONNECTION_NUM_PACKETS] bool;

// ----------------------------------------------------------------

netcode_t :: struct {
    initialized: bool;
}

netcode: netcode_t;

netcode_log :: (flags: Log_Flags, format_string: string, args: .. Any, loc := #caller_location) {
    #if ENABLE_LOGGING {
        log(format_string, ..args, loc, flags,, temp);
    }
}

// ----------------------------------------------------------------

// This accepts an IPv4 address *or* an IPv6 address in string form. See the comments on the `address_init_v4`
// and `address_init_v6` methods to learn about valid formats.
netcode_parse_address :: (address_string_in: string, address: *netcode_address_t) -> int {
    if address_string_in.count == 0 {
        return NETCODE_ERROR;
    }

    addr, remainder := address_init_auto_detect(address_string_in);

    // We don't expect any remainder when parsing address strings here. They are proxied through Yojimbo.
    if remainder.count > 0 {
        return NETCODE_ERROR;
    }

    if addr.type == {
        case .IPv4;
            address.type = NETCODE_ADDRESS_IPV4;
            address.port = addr.port;
            array_copy(address.data.ipv4, addr.data.v4);
            return NETCODE_OK;
        case .IPv6;
            address.type = NETCODE_ADDRESS_IPV6;
            address.port = addr.port;
            array_copy(address.data.ipv6, addr.data.v6);
            return NETCODE_OK;
    }

    return NETCODE_ERROR;
}

netcode_address_to_string :: (address: netcode_address_t) -> string {
    ip: IPAddress;

    if address.type == {
        case NETCODE_ADDRESS_IPV4;
            ip.type = .IPv4;
            ip.port = address.port;
            array_copy(ip.data.v4, address.data.ipv4);
        case NETCODE_ADDRESS_IPV6;
            ip.type = .IPv6;
            ip.port = address.port;
            array_copy(ip.data.v6, address.data.ipv6);
    }

    return address_to_string(ip);
}

netcode_address_equal :: (a: netcode_address_t, b: netcode_address_t) -> bool {
    // TODO(dlb): De-dupe this code with Yojimbo/address.jai
    if a.type != b.type return false;
    if a.port != b.port return false;
    if a.type == {
        case NETCODE_ADDRESS_NONE;
            return true;
        case NETCODE_ADDRESS_IPV4;
            return array_equal(a.data.ipv4, b.data.ipv4);
        case NETCODE_ADDRESS_IPV6;
            return array_equal(a.data.ipv6, b.data.ipv6);
    }

    assert(false, "Invalid address type");
    return false;
}

// ----------------------------------------------------------------

netcode_socket_t :: struct {
    handle: Socket = INVALID_SOCKET;
    address: netcode_address_t;
}

netcode_socket_holder_t :: struct {
    ipv4: netcode_socket_t;
    ipv6: netcode_socket_t;
}

NETCODE_SOCKET_ERROR_NONE                              :: 0;
NETCODE_SOCKET_ERROR_CREATE_FAILED                     :: 1;
NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED           :: 2;
NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED          :: 3;
NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED             :: 4;
NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED             :: 5;
NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED                  :: 6;
NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED                  :: 7;
NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED          :: 8;
NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED          :: 9;
NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED :: 10;

netcode_socket_destroy :: (socket: *netcode_socket_t) {
    assert(socket != null);
    assert(netcode.initialized);

    close_and_reset(*socket.handle);
}

netcode_socket_create :: (_socket: *netcode_socket_t, address: netcode_address_t, send_buffer_size: s32, receive_buffer_size: s32) -> int {
    assert(_socket != null);
    assert(netcode.initialized);

    assert(address.type != NETCODE_ADDRESS_NONE);
    _socket.address = address;

    // create socket
    addressFamily := cast(s32) (ifx address.type == NETCODE_ADDRESS_IPV6 then AF_INET6 else AF_INET);
    _socket.handle = socket(addressFamily, SOCK.DGRAM, IPPROTO.UDP);

    if _socket.handle == INVALID_SOCKET {
        netcode_log(.ERROR, "error: failed to create socket\n");
        return NETCODE_SOCKET_ERROR_CREATE_FAILED;
    }

    // IMPORTANT: tell windows we don't want to receive any connection reset messages
    // for this socket, otherwise recvfrom errors out when client sockets disconnect hard
    // in response to ICMP messages.
    #if OS == .WINDOWS {
        SIO_UDP_CONNRESET :: 0x9800000C;  //_WSAIOW(IOC_VENDOR, 12)
        bNewBehavior := cast(s32) 0;      // Win32 BOOL false
        dwBytesReturned := cast(u32) 0;   // Win32 DWORD
        result := WSAIoctl(_socket.handle, SIO_UDP_CONNRESET, *bNewBehavior, size_of(type_of(bNewBehavior)), null, 0, *dwBytesReturned, null, null);
        if result != 0 {
            error_code := get_last_socket_error();
            error_string := System.get_error_string(error_code);
            netcode_log(.ERROR, "error: failed to disable UDP CONNRESET (port unreachable) message reporting on socket. %: %\n", error_code, error_string);
            return NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED;
        }
    }

    // force IPv6 only if necessary

    if address.type == NETCODE_ADDRESS_IPV6 {
        yes: s32 = 1;  // Win32 BOOL
        if setsockopt(_socket.handle, cast(s32) IPPROTO.IPPROTO_IPV6, IPV6_V6ONLY, cast(*void) *yes, size_of(s32)) != 0 {
            netcode_log(.ERROR, "error: failed to set socket ipv6 only\n");
            netcode_socket_destroy(_socket);
            return NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED;
        }
    }

    // increase socket send and receive buffer sizes

    if setsockopt(_socket.handle, SOL_SOCKET, SO_SNDBUF, cast(*void) *send_buffer_size, size_of(s32)) != 0 {
        netcode_log(.ERROR, "error: failed to set socket send buffer size\n");
        netcode_socket_destroy(_socket);
        return NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
    }

    if setsockopt(_socket.handle, SOL_SOCKET, SO_RCVBUF, cast(*void) *receive_buffer_size, size_of(s32)) != 0 {
        netcode_log(.ERROR, "error: failed to set socket receive buffer size\n");
        netcode_socket_destroy(_socket);
        return NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
    }

    // bind to port
    if address.type == NETCODE_ADDRESS_IPV6 {
        addr: [8] u16;

        // HACK(dlb): Reverse the bytes (network order -> host order) because Socket module expects host order
        // TODO(dlb): We should probably just call the real bind() function ourselves in this case -_-
        for 0..7 {
            addr[it] = address.data.ipv6[7-it];
        }

        if bind(_socket.handle, cast,force([16] u8) addr, address.port) < 0 {
            netcode_log(.ERROR, "error: failed to bind socket (ipv6)\n");
            netcode_socket_destroy(_socket);
            return NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED;
        }
    } else {
        addr: [4] u8;

        // HACK(dlb): Reverse the bytes (network order -> host order) because Socket module expects host order
        // TODO(dlb): We should probably just call the real bind() function ourselves in this case -_-
        for 0..3 {
            addr[it] = addr[3-it];
        }

        if bind(_socket.handle, (cast(*u32) addr.data).*, address.port) < 0 {
            netcode_log(.ERROR, "error: failed to bind socket (ipv4)\n");
            netcode_socket_destroy(_socket);
            return NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED;
        }
    }

    // if bound to port 0 find the actual port we got
    if address.port == 0 {
        if address.type == NETCODE_ADDRESS_IPV6 {
            sin: sockaddr_in6;
            len: socklen_t = size_of(type_of(sin));
            if getsockname(_socket.handle, cast(*sockaddr) *sin, *len) == -1 {
                netcode_log(.ERROR, "error: failed to get socket port (ipv6)\n");
                netcode_socket_destroy(_socket);
                return NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED;
            }
            _socket.address.port = ntohs(sin.sin6_port);
        } else {
            sin: sockaddr_in;
            len: socklen_t = size_of(type_of(sin));
            if getsockname(_socket.handle, cast(*sockaddr) *sin, *len) == -1 {
                netcode_log(.ERROR, "error: failed to get socket port (ipv4)\n");
                netcode_socket_destroy(_socket);
                return NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED;
            }
            _socket.address.port = ntohs(sin.sin_port);
        }
    }

    // set non-blocking io
    set_blocking(_socket.handle, false);

    return NETCODE_SOCKET_ERROR_NONE;
}

netcode_socket_send_packet :: (socket: netcode_socket_t, to: netcode_address_t, packet_data: [] u8) -> bool {
    assert(socket.handle != INVALID_SOCKET);
    assert(to.type == NETCODE_ADDRESS_IPV6 || to.type == NETCODE_ADDRESS_IPV4);
    assert(packet_data.count > 0);

    if to.type == NETCODE_ADDRESS_IPV6 {
        socket_address: sockaddr_in6;
        socket_address.sin6_family = AF_INET6;
        for 0..7 {
            (cast(*u16) *socket_address.sin6_addr)[it] = htons(to.data.ipv6[it]);
        }
        socket_address.sin6_port = htons(to.port);
        result := sendto(socket.handle, packet_data.data, xx packet_data.count, 0, cast(*sockaddr) *socket_address, size_of(sockaddr_in6));
        if result == SOCKET_ERROR {
            netcode_log(.ERROR, "error: failed send packet (ipv6)\n");
            return false;
        }
    } else if to.type == NETCODE_ADDRESS_IPV4 {
        socket_address: sockaddr_in;
        socket_address.sin_family = AF_INET;
        #if OS == .WINDOWS {
            addr: *u32 = *socket_address.sin_addr.S_un.S_addr;
        } else {
            addr: *u32 = *socket_address.sin_addr.s_addr;
        }
        addr.* = ((cast(u32) to.data.ipv4[0])      ) |
                 ((cast(u32) to.data.ipv4[1]) << 8 ) |
                 ((cast(u32) to.data.ipv4[2]) << 16) |
                 ((cast(u32) to.data.ipv4[3]) << 24);
        socket_address.sin_port = htons(to.port);
        result := sendto(socket.handle, packet_data.data, xx packet_data.count, 0, cast(*sockaddr) *socket_address, size_of(sockaddr_in));
        if result == SOCKET_ERROR {
            netcode_log(.ERROR, "error: failed send packet (ipv4)\n");
            return false;
        }
    }

    return true;
}

// TODO(dlb): Make `from` a return value
netcode_socket_receive_packet :: (socket: netcode_socket_t, from: *netcode_address_t, packet_buf: [] u8) -> packet_bytes: int {
    assert(socket.handle != INVALID_SOCKET);
    assert(from != null);
    assert(packet_buf.count > 0);

    sockaddr_from: sockaddr_storage;
    from_length: socklen_t = cast(socklen_t) size_of(type_of(sockaddr_from));

    bytes_read := recvfrom(socket.handle, packet_buf.data, xx packet_buf.count, 0, cast(*sockaddr) *sockaddr_from, *from_length);
    if bytes_read == SOCKET_ERROR {
        error := get_last_socket_error();
        if error == SOCKET_WOULDBLOCK {
            return 0;
        }

        netcode_log(.ERROR, "error: recvfrom failed with error %\n", error);
        return 0;
    }

    if sockaddr_from.ss_family == AF_INET6 {
        addr_ipv6 := cast(*sockaddr_in6) *sockaddr_from;
        from.type = NETCODE_ADDRESS_IPV6;
        for 0..7 {
            from.data.ipv6[it] = ntohs((cast(*u16) *addr_ipv6.sin6_addr)[it]);
        }
        from.port = ntohs(addr_ipv6.sin6_port);
    } else if sockaddr_from.ss_family == AF_INET {
        addr_ipv4 := cast(*sockaddr_in) *sockaddr_from;
        from.type = NETCODE_ADDRESS_IPV4;
        #if OS == .WINDOWS {
            addr: u32 = addr_ipv4.sin_addr.S_un.S_addr;
        } else {
            addr: u32 = addr_ipv4.sin_addr.s_addr;
        }
        from.data.ipv4[0] = cast(u8) ((addr & 0x000000FF)      );
        from.data.ipv4[1] = cast(u8) ((addr & 0x0000FF00) >> 8 );
        from.data.ipv4[2] = cast(u8) ((addr & 0x00FF0000) >> 16);
        from.data.ipv4[3] = cast(u8) ((addr & 0xFF000000) >> 24);
        from.port = ntohs(addr_ipv4.sin_port);
    } else {
        assert(false, "Invalid address family");
        return 0;
    }

    assert(bytes_read >= 0);
    return bytes_read;
}

// ----------------------------------------------------------------

netcode_write_uint8 :: (p: **u8, value: u8) {
    p.*.* = value;
    p.* += 1;
}

netcode_write_uint16 :: (p: **u8, value: u16) {
    p.*[0] = cast(u8) (value & 0xFF);
    p.*[1] = cast(u8) (value >> 8);
    p.* += 2;
}

netcode_write_uint32 :: (p: **u8, value: u32) {
    p.*[0] = cast(u8) (value & 0xFF);
    p.*[1] = cast(u8) ((value >> 8 ) & 0xFF);
    p.*[2] = cast(u8) ((value >> 16) & 0xFF);
    p.*[3] = cast(u8) (value >> 24);
    p.* += 4;
}

netcode_write_uint64 :: (p: **u8, value: u64) {
    p.*[0] = cast(u8) (value & 0xFF);
    p.*[1] = cast(u8) ((value >> 8 ) & 0xFF);
    p.*[2] = cast(u8) ((value >> 16) & 0xFF);
    p.*[3] = cast(u8) ((value >> 24) & 0xFF);
    p.*[4] = cast(u8) ((value >> 32) & 0xFF);
    p.*[5] = cast(u8) ((value >> 40) & 0xFF);
    p.*[6] = cast(u8) ((value >> 48) & 0xFF);
    p.*[7] = cast(u8) (value >> 56);
    p.* += 8;
}

netcode_write_bytes :: (p: **u8, byte_array: [] u8) {
    for byte_array {
        netcode_write_uint8(p, it);
    }
}

netcode_read_uint8 :: (p: **u8) -> u8 {
    value: u8 = p.*.*;
    p.* += 1;
    return value;
}

netcode_read_uint16 :: (p: **u8) -> u16 {
    value: u16 = p.*[0];
    value |= (cast(u16) (p.*[1])) << 8;
    p.* += 2;
    return value;
}

netcode_read_uint32 :: (p: **u8) -> u32 {
    value: u32 = p.*[0];
    value |= (cast(u32) (p.*[1])) << 8;
    value |= (cast(u32) (p.*[2])) << 16;
    value |= (cast(u32) (p.*[3])) << 24;
    p.* += 4;
    return value;
}

netcode_read_uint64 :: (p: **u8) -> u64 {
    value: u64 = p.*[0];
    value |= (cast(u64) (p.*[1])) << 8;
    value |= (cast(u64) (p.*[2])) << 16;
    value |= (cast(u64) (p.*[3])) << 24;
    value |= (cast(u64) (p.*[4])) << 32;
    value |= (cast(u64) (p.*[5])) << 40;
    value |= (cast(u64) (p.*[6])) << 48;
    value |= (cast(u64) (p.*[7])) << 56;
    p.* += 8;
    return value;
}

netcode_read_bytes :: (p: **u8, byte_array: [] u8) {
    for * byte_array {
        it.* = netcode_read_uint8(p);
    }
}

// ----------------------------------------------------------------
// TODO(dlb): Don't pretend to encrypt important data?
// HACK(dlb): !!! INSECURE / FAKE / BAD / DANGEROUS !!!
// Sodium placeholders to avoid the dependency while porting
// ----------------------------------------------------------------

// TODO(dlb): This should be crypto random
randombytes_buf :: (buf: [] u8) {
    for 0..buf.count-1 {
        buf[it] = cast(u8) (random_get() & 0xFF);
    }
}

crypto_aead_xchacha20poly1305_ietf_encrypt :: (
    c      : *u8,   // [out] encrypted
    clen_p : *u64,  // [out] encrypted length
    m      : *u8,   // [in] plaintext
    mlen   : u64,   // [in] plaintext length
    ad     : *u8,   // [in] additional data
    adlen  : u64,   // [in] additional data length
    nsec   : *u8,   // [in] secret nonce
    npub   : *u8,   // [in] public nonce
    k      : *u8    // [in] key
) -> int {
    if !encrypt_security_warning_shown {
        print("CRITICAL: FAKE ENCRYPTION ENABLED. YOUR DATA IS NOT SAFE!\n");
        encrypt_security_warning_shown = true;
    }
    clen_p.* = mlen + NETCODE_MAC_BYTES;
    return 0;
}

crypto_aead_xchacha20poly1305_ietf_decrypt :: (
    m      : *u8,   // [out] plaintext
    mlen_p : *u64,  // [out] plaintext length
    nsec   : *u8,   // [in] secret nonce
    c      : *u8,   // [in] encrypted
    clen   : u64,   // [in] encrypted length
    ad     : *u8,   // [in] additional data
    adlen  : u64,   // [in] additional data length
    npub   : *u8,   // [in] public nonce
    k      : *u8    // [in] key
) -> int {
    if !decrypt_security_warning_shown {
        print("CRITICAL: FAKE DECRYPTION ENABLED. YOUR DATA IS NOT SAFE!\n");
        decrypt_security_warning_shown = true;
    }
    mlen_p.* = clen - NETCODE_MAC_BYTES;
    return 0;
}

// NOTE: These are different in the real implementation, but their arguments are the same so we can re-use the placeholders
crypto_aead_chacha20poly1305_ietf_encrypt :: crypto_aead_xchacha20poly1305_ietf_encrypt;
crypto_aead_chacha20poly1305_ietf_decrypt :: crypto_aead_xchacha20poly1305_ietf_decrypt;

// ----------------------------------------------------------------

netcode_generate_key :: (key: EncryptionKeyBuf) {
    randombytes_buf(key);
}

netcode_generate_nonce :: (nonce: BigNonceBuf) {
    randombytes_buf(nonce);
}

netcode_random_bytes :: (data: [] u8) {
    assert(data.count > 0);

    randombytes_buf(data);
}

// the nonce here is expected to be random bytes which differ for each message
netcode_encrypt_aead_bignonce :: (message: [] u8, header: [] u8, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    encrypted_length: u64;

    err := crypto_aead_xchacha20poly1305_ietf_encrypt(
        message.data, *encrypted_length,
        message.data, cast(u64) message.count,
        header.data, cast(u64) header.count,
        null,
        nonce.data, key.data
    );

    if err != 0 {
        return NETCODE_ERROR;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    // HACK(dlb): Put random nonsense in the MAC to make the test pass without importing libsodium
    /////////////////////////////////////////////////////////////////////////////////////////////////////////
    if !fake_mac_security_warning_shown {
        print("CRITICAL: FAKE MAC AUTH ENABLED. YOUR DATA IS NOT SAFE!\n");
        fake_mac_security_warning_shown = true;
    }
    mac := message.data + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES;
    hash := netcode_hash_data(message) ^ netcode_hash_data(header) ^ netcode_hash_data(nonce);
    memcpy(mac, *hash, size_of(type_of(hash)));
    /////////////////////////////////////////////////////////////////////////////////////////////////////////

    assert(cast(int) encrypted_length == message.count + NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// the nonce here is expected to be random bytes which differ for each message
netcode_decrypt_aead_bignonce :: (message: [] u8, header: [] u8, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    decrypted_length: u64;

    err := crypto_aead_xchacha20poly1305_ietf_decrypt(
        message.data, *decrypted_length,
        null,
        message.data, cast(u64) message.count,
        header.data, cast(u64) header.count,
        nonce.data, key.data
    );

    if err != 0 {
        return NETCODE_ERROR;
    }

    assert(cast(int) decrypted_length == message.count - NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// the nonce here is expected to sequential for each message
netcode_encrypt_aead :: (message: [] u8, header: [] u8, nonce: NonceBuf, key: EncryptionKeyBuf) -> int {
    encrypted_length: u64;

    err := crypto_aead_chacha20poly1305_ietf_encrypt(
        message.data, *encrypted_length,
        message.data, cast(u64) message.count,
        header.data, cast(u64) header.count,
        null,
        nonce.data, key.data
    );

    if err != 0 {
        return NETCODE_ERROR;
    }

    assert(cast(int) encrypted_length == message.count + NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// the nonce here is expected to sequential for each message
netcode_decrypt_aead :: (message: [] u8, header: [] u8, nonce: NonceBuf, key: EncryptionKeyBuf) -> int {
    decrypted_length: u64;

    err := crypto_aead_chacha20poly1305_ietf_decrypt(
        message.data, *decrypted_length,
        null,
        message.data, cast(u64) message.count,
        header.data, cast(u64) header.count,
        nonce.data, key.data
    );

    if err != 0 {
        return NETCODE_ERROR;
    }

    assert(cast(int) decrypted_length == message.count - NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// ----------------------------------------------------------------

netcode_connect_token_private_t :: struct {
    client_id            : u64;
    timeout_seconds      : Apollo_Time;
    num_server_addresses : int;
    server_addresses     : [NETCODE_MAX_SERVERS_PER_CONNECT] netcode_address_t;
    client_to_server_key : EncryptionKeyBuf;
    server_to_client_key : EncryptionKeyBuf;
    user_data            : UserDataBuf;
}

netcode_generate_connect_token_private :: (connect_token: *netcode_connect_token_private_t, client_id: u64, timeout_seconds: Apollo_Time, server_addresses: [] netcode_address_t, user_data: UserDataBuf) {
    assert(connect_token != null);
    assert(server_addresses.count > 0);
    assert(server_addresses.count <= NETCODE_MAX_SERVERS_PER_CONNECT);

    connect_token.client_id = client_id;
    connect_token.timeout_seconds = timeout_seconds;
    connect_token.num_server_addresses = server_addresses.count;

    for server_addresses {
        connect_token.server_addresses[it_index] = it;
    }

    netcode_generate_key(connect_token.client_to_server_key);
    netcode_generate_key(connect_token.server_to_client_key);

    if user_data.count > 0 {
        array_copy(connect_token.user_data, user_data);
    }
}

netcode_write_connect_token_private :: (connect_token: netcode_connect_token_private_t, token_data_buffer: ConnectTokenPrivateDataBuf) {
    assert(connect_token.num_server_addresses > 0);
    assert(connect_token.num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT);

    start := token_data_buffer.data;
    cursor := token_data_buffer.data;

    netcode_write_uint64(*cursor, connect_token.client_id);
    // NOTE(dlb): no_check because it's sometimes -1 for "no timeout". There's probably a better way to handle this? E.g. serialize a bit flag instead.
    netcode_write_uint32(*cursor, cast,no_check(u32) to_milliseconds(connect_token.timeout_seconds));
    netcode_write_uint32(*cursor, cast(u32) connect_token.num_server_addresses);

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];
        if address.type == NETCODE_ADDRESS_IPV4 {
            netcode_write_uint8(*cursor, NETCODE_ADDRESS_IPV4);
            for it_byte: 0..3 {
                netcode_write_uint8(*cursor, address.data.ipv4[it_byte]);
            }
            netcode_write_uint16(*cursor, address.port);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            netcode_write_uint8(*cursor, NETCODE_ADDRESS_IPV6);
            for it_byte: 0..7 {
                netcode_write_uint16(*cursor, address.data.ipv6[it_byte]);
            }
            netcode_write_uint16(*cursor, address.port);
        } else {
            assert(false, "Invalid address type");
        }
    }

    netcode_write_bytes(*cursor, connect_token.client_to_server_key);
    netcode_write_bytes(*cursor, connect_token.server_to_client_key);
    netcode_write_bytes(*cursor, connect_token.user_data);

    assert(pointer_diff(cursor, start) <= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES);
}

netcode_encrypt_connect_token_private :: (token_data_buffer: ConnectTokenPrivateDataBuf, version_info: VerionInfoBuf, protocol_id: u64, expire_timestamp: Apollo_Time, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    additional_data: [version_info.count + 8 + 8] u8;
    {
        ptr := additional_data.data;
        netcode_write_bytes(*ptr, version_info);
        netcode_write_uint64(*ptr, protocol_id);
        netcode_write_uint64(*ptr, cast(u64) to_milliseconds(expire_timestamp));
    }

    return netcode_encrypt_aead_bignonce(.{ NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES, token_data_buffer.data }, additional_data, nonce, key);
}

netcode_decrypt_connect_token_private :: (token_data_buffer: ConnectTokenPrivateDataBuf, version_info: VerionInfoBuf, protocol_id: u64, expire_timestamp: Apollo_Time, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    additional_data: [NETCODE_VERSION_INFO_BYTES + 8 + 8] u8;
    {
        ptr := additional_data.data;
        netcode_write_bytes(*ptr, version_info);
        netcode_write_uint64(*ptr, protocol_id);
        netcode_write_uint64(*ptr, cast(u64) to_milliseconds(expire_timestamp));
    }
    return netcode_decrypt_aead_bignonce(token_data_buffer, additional_data, nonce, key);
}

netcode_read_connect_token_private :: (token_data_buffer: ConnectTokenPrivateDataBuf, connect_token: *netcode_connect_token_private_t) -> int {
    assert(connect_token != null);

    cursor := token_data_buffer.data;

    connect_token.client_id = netcode_read_uint64(*cursor);
    connect_token.timeout_seconds = milliseconds_to_apollo(netcode_read_uint32(*cursor));
    connect_token.num_server_addresses = netcode_read_uint32(*cursor);

    if connect_token.num_server_addresses <= 0 {
        return NETCODE_ERROR;
    }
    if connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT {
        return NETCODE_ERROR;
    }

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];

        address.type = netcode_read_uint8(*cursor);
        if address.type == NETCODE_ADDRESS_IPV4 {
            for it_byte: 0..3 {
                address.data.ipv4[it_byte] = netcode_read_uint8(*cursor);
            }
            address.port = netcode_read_uint16(*cursor);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            for it_byte: 0..7 {
                address.data.ipv6[it_byte] = netcode_read_uint16(*cursor);
            }
            address.port = netcode_read_uint16(*cursor);
        } else {
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes(*cursor, connect_token.client_to_server_key);
    netcode_read_bytes(*cursor, connect_token.server_to_client_key);
    netcode_read_bytes(*cursor, connect_token.user_data);

    return NETCODE_OK;
}

// ----------------------------------------------------------------

netcode_challenge_token_t :: struct {
    client_id: u64;
    user_data: UserDataBuf;
}

netcode_write_challenge_token :: (challenge_token: netcode_challenge_token_t, token_buffer: ChallengeTokenBuf) {
    start := token_buffer.data;
    cursor := start;

    netcode_write_uint64(*cursor, challenge_token.client_id);
    netcode_write_bytes(*cursor, challenge_token.user_data);

    assert(pointer_diff(cursor, start) <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES);
}

netcode_encrypt_challenge_token :: (token_buffer: ChallengeTokenBuf, sequence: u64, key: EncryptionKeyBuf) -> int {
    nonce: [12] u8;
    {
        ptr := nonce.data;
        netcode_write_uint32(*ptr, 0);
        netcode_write_uint64(*ptr, sequence);
    }

    return netcode_encrypt_aead(.{ NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES, token_buffer.data }, .{}, nonce, key );
}

netcode_decrypt_challenge_token :: (token_buffer: ChallengeTokenBuf, sequence: u64, key: EncryptionKeyBuf) -> int {
    nonce: [12] u8;
    {
        ptr := nonce.data;
        netcode_write_uint32(*ptr, 0);
        netcode_write_uint64(*ptr, sequence);
    }

    return netcode_decrypt_aead(token_buffer, .{}, nonce, key);
}

netcode_read_challenge_token :: (token_buffer: ChallengeTokenBuf, challenge_token: *netcode_challenge_token_t) -> int {
    assert(challenge_token != null);

    start := token_buffer.data;
    cursor := start;

    challenge_token.client_id = netcode_read_uint64(*cursor);
    netcode_read_bytes(*cursor, challenge_token.user_data);

    assert(pointer_diff(cursor, start) == 8 + NETCODE_USER_DATA_BYTES);
    return NETCODE_OK;
}

// ----------------------------------------------------------------

// TODO(dlb): Make this an enum
NETCODE_CONNECTION_REQUEST_PACKET    :: 0;
NETCODE_CONNECTION_DENIED_PACKET     :: 1;
NETCODE_CONNECTION_CHALLENGE_PACKET  :: 2;
NETCODE_CONNECTION_RESPONSE_PACKET   :: 3;
NETCODE_CONNECTION_KEEP_ALIVE_PACKET :: 4;
NETCODE_CONNECTION_PAYLOAD_PACKET    :: 5;
NETCODE_CONNECTION_DISCONNECT_PACKET :: 6;
NETCODE_CONNECTION_NUM_PACKETS       :: 7;

netcode_connection_packet_t :: struct {
    type: u8;
}

netcode_connection_request_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_REQUEST_PACKET;

    version_info                   : VerionInfoBuf;
    protocol_id                    : u64;
    connect_token_expire_timestamp : Apollo_Time;
    connect_token_nonce            : BigNonceBuf;
    connect_token_data             : ConnectTokenPrivateDataBuf;
}

netcode_connection_denied_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_DENIED_PACKET;
}

netcode_connection_challenge_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_CHALLENGE_PACKET;

    challenge_token_sequence : u64;
    challenge_token_data     : ChallengeTokenBuf;
}

netcode_connection_response_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_RESPONSE_PACKET;

    challenge_token_sequence : u64;
    challenge_token_data     : ChallengeTokenBuf;
}

netcode_connection_keep_alive_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;

    client_index : int;
    max_clients  : int;
}

netcode_connection_payload_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_PAYLOAD_PACKET;

    // NOTE(dlb): This memory is owned by the payload packet and is allocated contiguously after the packet itself!
    payload_data : [] u8;
}

netcode_connection_disconnect_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_DISCONNECT_PACKET;
}

netcode_create_payload_packet :: (payload_bytes: int) -> *netcode_connection_payload_packet_t {
    assert(payload_bytes >= 0);
    assert(payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES);

    // NOTE(dlb): Ensure there's a full word at the end of the byte array prevent bit_reader reading out of bounds
    // later. If the struct were not aligned on 4-byte word boundaries, we would also need to align it, but it is, so
    // I'm just asserting that it says that way.
    header_size := size_of(netcode_connection_payload_packet_t);
    assert_equal(header_size % 4, 0);
    buffer_size := align_forward(header_size + payload_bytes + 3, 4);
    buffer := NewArray(buffer_size, u8);
    if buffer.count == 0 {
        return null;
    }

    packet := cast(*netcode_connection_payload_packet_t) buffer.data;
    Initialize(packet);
    packet.payload_data = .{ payload_bytes, buffer.data + header_size };
    assert_equal(cast(int) packet.payload_data.data % 4, 0);  // must be word-aligned!

    return packet;
}

netcode_free_payload_packet :: (payload_data: [] u8) {
    assert(payload_data.count > 0);

    // NOTE(dlb): Contiguous allocation of struct+buffer. See netcode_create_payload_packet().
    header_size := size_of(netcode_connection_payload_packet_t);
    free(payload_data.data - header_size);
}

netcode_context_t :: struct {
    write_packet_key: EncryptionKeyBuf;
    read_packet_key: EncryptionKeyBuf;
}

netcode_sequence_number_bytes_required :: (sequence: u64) -> int {
    mask: u64 = 0xFF00000000000000;
    for 0..6 {
        if sequence & mask {
            return 8 - it; // n bytes
        }
        mask >>= 8;
    }
    return 1;  // 1 byte
}

netcode_write_packet :: (packet: *netcode_connection_packet_t, buffer: [] u8, sequence: u64, write_packet_key: EncryptionKeyBuf, protocol_id: u64) -> int {
    assert(packet != null);
    assert(buffer.count > 0);
    assert(write_packet_key.count > 0);

    if packet.type == NETCODE_CONNECTION_REQUEST_PACKET {
        // connection request packet: first byte is zero

        assert(buffer.count >= 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

        p := cast(*netcode_connection_request_packet_t) packet;

        start := buffer.data;
        cursor := start;

        netcode_write_uint8(*cursor, NETCODE_CONNECTION_REQUEST_PACKET);
        netcode_write_bytes(*cursor, p.version_info);
        netcode_write_uint64(*cursor, p.protocol_id);
        netcode_write_uint64(*cursor, cast(u64) to_milliseconds(p.connect_token_expire_timestamp));
        netcode_write_bytes(*cursor, p.connect_token_nonce);
        netcode_write_bytes(*cursor, p.connect_token_data);

        assert(pointer_diff(cursor, start) == 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

        return cast(int) pointer_diff(cursor, start);
    } else {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        start := buffer.data;
        cursor := start;

        sequence_bytes := cast(u8) netcode_sequence_number_bytes_required(sequence);

        assert(sequence_bytes >= 1);
        assert(sequence_bytes <= 8);

        assert(packet.type <= 0xF);  // huh? that's not even the max packet type bruh

        prefix_byte := packet.type | (sequence_bytes << 4);

        netcode_write_uint8(*cursor, prefix_byte);

        // write the variable length sequence number [1,8] bytes.

        sequence_temp := sequence;

        for 0..sequence_bytes-1 {
            netcode_write_uint8(*cursor, cast(u8) (sequence_temp & 0xFF));
            sequence_temp >>= 8;
        }

        // write packet data according to type. this data will be encrypted.

        encrypted_start := cursor;

        if packet.type == {
            case NETCODE_CONNECTION_DENIED_PACKET;
                // ...
            case NETCODE_CONNECTION_CHALLENGE_PACKET;
                p := cast(*netcode_connection_challenge_packet_t) packet;
                netcode_write_uint64(*cursor, p.challenge_token_sequence );
                netcode_write_bytes(*cursor, p.challenge_token_data);
            case NETCODE_CONNECTION_RESPONSE_PACKET;
                p := cast(*netcode_connection_response_packet_t) packet;
                netcode_write_uint64(*cursor, p.challenge_token_sequence);
                netcode_write_bytes(*cursor, p.challenge_token_data);
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
                p := cast(*netcode_connection_keep_alive_packet_t) packet;
                netcode_write_uint32(*cursor, cast(u32) p.client_index);
                netcode_write_uint32(*cursor, cast(u32) p.max_clients);
            case NETCODE_CONNECTION_PAYLOAD_PACKET;
                p := cast(*netcode_connection_payload_packet_t) packet;

                assert(p.payload_data.count <= NETCODE_MAX_PAYLOAD_BYTES);

                netcode_write_bytes(*cursor, p.payload_data);
            case NETCODE_CONNECTION_DISCONNECT_PACKET;
                // ...
            case;
                assert(false, "invalid connection packet type");
        }

        assert(pointer_diff(cursor, start) <= buffer.count - NETCODE_MAC_BYTES);

        encrypted_finish := cursor;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

        additional_data: [NETCODE_VERSION_INFO_BYTES + 8 + 1] u8;
        {
            ptr := additional_data.data;
            netcode_write_bytes(*ptr, NETCODE_VERSION_INFO);
            netcode_write_uint64(*ptr, protocol_id);
            netcode_write_uint8(*ptr, prefix_byte);
        }

        nonce: [12] u8;
        {
            ptr := nonce.data;
            netcode_write_uint32(*ptr, 0);
            netcode_write_uint64(*ptr, sequence);
        }

        if netcode_encrypt_aead(.{ pointer_diff(encrypted_finish, encrypted_start), encrypted_start }, additional_data, nonce, write_packet_key) != NETCODE_OK {
            return NETCODE_ERROR;
        }

        cursor += NETCODE_MAC_BYTES;
        assert(pointer_diff(cursor, start) <= buffer.count);

        return pointer_diff(cursor, start);
    }
}

netcode_replay_protection_t :: struct {
    most_recent_sequence : u64;
    received_packet      : [NETCODE_REPLAY_PROTECTION_BUFFER_SIZE] u64;
}

netcode_replay_protection_reset :: (replay_protection: *netcode_replay_protection_t) {
    assert(replay_protection != null);

    replay_protection.most_recent_sequence = 0;
    array_fill_byte(replay_protection.received_packet, 0xFF);
}

netcode_replay_protection_already_received :: (replay_protection: *netcode_replay_protection_t, sequence: u64) -> bool {
    assert(replay_protection != null);

    // NOTE(dlb): If we sent a packet every millisecond it would take roughly 584 million years for
    // this to wrap, assuming we always start a zero. As such, we elide wraparound protection.
    if sequence + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE <= replay_protection.most_recent_sequence {
        return true;
    }

    index := cast(int) (sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE);

    if replay_protection.received_packet[index] == 0x_FFFF_FFFF_FFFF_FFFF {
        return false;
    }

    if replay_protection.received_packet[index] >= sequence {
        return true;
    }

    return false;
}

netcode_replay_protection_advance_sequence :: (replay_protection: *netcode_replay_protection_t, sequence: u64) {
    assert(replay_protection != null);

    // NOTE(dlb): No wraparound protection, it's big enough (see above).
    if sequence > replay_protection.most_recent_sequence {
        replay_protection.most_recent_sequence = sequence;
    }

    index := cast(int) (sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE);

    replay_protection.received_packet[index] = sequence;
}

netcode_read_packet :: (
    buffer            : [] u8,
    read_packet_key   : EncryptionKeyBuf,
    protocol_id       : u64,
    current_timestamp : Apollo_Time,
    private_key       : *EncryptionKeyBuf,
    allowed_packets   : AllowedPacketsBuf,  // NOTE(dlb): Could be a Bit_Array, but it's on the stack, so I probably don't care?
    replay_protection : *netcode_replay_protection_t
) -> packet: *netcode_connection_packet_t, sequence: u64 {
    if buffer.count < 1 {
        netcode_log(.VERBOSE_ONLY, "ignored packet. buffer length is less than 1\n");
        return null, 0;
    }

    start := buffer.data;
    cursor := start;

    prefix_byte := netcode_read_uint8(*cursor);

    if prefix_byte == NETCODE_CONNECTION_REQUEST_PACKET {
        // connection request packet: first byte is zero

        if !allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. packet type is not allowed\n");
            return null, 0;
        }

        if buffer.count != 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. bad packet length (expected %, got %)\n", 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, buffer.count);
            return null, 0;
        }

        if private_key == null {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. no private key\n");
            return null, 0;
        }

        version_info: VerionInfoBuf;
        netcode_read_bytes(*cursor, version_info);
        if !array_equal(version_info, NETCODE_VERSION_INFO) {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. bad version info\n");
            return null, 0;
        }

        packet_protocol_id := netcode_read_uint64(*cursor);
        if packet_protocol_id != protocol_id {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. wrong protocol id. expected %, got %\n", protocol_id, packet_protocol_id);
            return null, 0;
        }

        packet_connect_token_expire_timestamp := milliseconds_to_apollo(cast(s64) netcode_read_uint64(*cursor));
        if packet_connect_token_expire_timestamp <= current_timestamp {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. connect token expired\n");
            return null, 0;
        }

        packet_connect_token_nonce: BigNonceBuf;
        netcode_read_bytes(*cursor, packet_connect_token_nonce);

        assert(pointer_diff(cursor, start) == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES);

        decrypt_token_result := netcode_decrypt_connect_token_private(
            cast(ConnectTokenPrivateDataBuf) cursor,
            version_info,
            protocol_id,
            packet_connect_token_expire_timestamp,
            packet_connect_token_nonce,
            private_key.*
        );
        if decrypt_token_result != NETCODE_OK {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. connect token failed to decrypt\n");
            return null, 0;
        }

        packet := New(netcode_connection_request_packet_t);
        if packet == null {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. failed to allocate packet\n");
            return null, 0;
        }
        assert(packet.type == NETCODE_CONNECTION_REQUEST_PACKET);

        packet.version_info = version_info;
        packet.protocol_id = packet_protocol_id;
        packet.connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
        packet.connect_token_nonce = packet_connect_token_nonce;

        netcode_read_bytes(*cursor, packet.connect_token_data);

        assert(pointer_diff(cursor, start) == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

        return packet, 0;  // first packet is sequence number 0 of course, not an error case!
    } else {
        // *** encrypted packets ***

        if read_packet_key.count == 0 {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. no read packet key for this address\n");
            return null, 0;
        }

        if buffer.count < 1 + 1 + NETCODE_MAC_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. packet is too small to be valid (% bytes)\n", buffer.count);
            return null, 0;
        }

        // extract the packet type and number of sequence bytes from the prefix byte

        packet_type := prefix_byte & 0xF;

        if packet_type >= NETCODE_CONNECTION_NUM_PACKETS {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. packet type % is invalid\n", packet_type);
            return null, 0;
        }

        if !allowed_packets[packet_type] {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. packet type % is not allowed\n", packet_type);
            return null, 0;
        }

        sequence_bytes := prefix_byte >> 4;

        if sequence_bytes < 1 || sequence_bytes > 8 {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. sequence bytes % is out of range [1,8]\n", sequence_bytes);
            return null, 0;
        }

        if buffer.count < 1 + sequence_bytes + NETCODE_MAC_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n");
            return null, 0;
        }

        // read variable length sequence number [1,8]

        sequence: u64;
        for 0..sequence_bytes-1 {
            value := netcode_read_uint8(*cursor);
            sequence |= (cast(u64) value) << (8 * it);
        }

        // ignore the packet if it has already been received

        if replay_protection != null && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET {
            if netcode_replay_protection_already_received(replay_protection, sequence) {
                netcode_log(.VERBOSE_ONLY, "ignored packet. sequence % already received (replay protection)\n", sequence);
                return null, 0;
            }
        }

        // decrypt the per-packet type data

        additional_data: [NETCODE_VERSION_INFO_BYTES + 8 + 1] u8;
        {
            ptr := additional_data.data;
            netcode_write_bytes(*ptr, NETCODE_VERSION_INFO);
            netcode_write_uint64(*ptr, protocol_id);
            netcode_write_uint8(*ptr, prefix_byte);
        }

        nonce: [12] u8;
        {
            ptr := nonce.data;
            netcode_write_uint32(*ptr, 0);
            netcode_write_uint64(*ptr, sequence);
        }

        encrypted_bytes := (buffer.count - pointer_diff(cursor, start));

        if encrypted_bytes < NETCODE_MAC_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. encrypted payload is too small\n");
            return null, 0;
        }

        if netcode_decrypt_aead(.{ encrypted_bytes, cursor }, additional_data, nonce, read_packet_key) != NETCODE_OK {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. failed to decrypt\n");
            return null, 0;
        }

        decrypted_bytes := encrypted_bytes - NETCODE_MAC_BYTES;

        // update the latest replay protection sequence #

        if replay_protection != null && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET {
            netcode_replay_protection_advance_sequence(replay_protection, sequence);
        }

        // process the per-packet type data that was just decrypted

        if packet_type == {
            case NETCODE_CONNECTION_DENIED_PACKET;
                if decrypted_bytes != 0 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection denied packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_denied_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection denied packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_DENIED_PACKET);

                return packet, sequence;
            case NETCODE_CONNECTION_CHALLENGE_PACKET;
                if decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES {
                    netcode_log(.VERBOSE_ONLY, "ignored connection challenge packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_challenge_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection challenge packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_CHALLENGE_PACKET);

                packet.challenge_token_sequence = netcode_read_uint64(*cursor);
                netcode_read_bytes(*cursor, packet.challenge_token_data);

                return packet, sequence;
            case NETCODE_CONNECTION_RESPONSE_PACKET;
                if decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES {
                    netcode_log(.VERBOSE_ONLY, "ignored connection response packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_response_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection response packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_RESPONSE_PACKET);

                packet.challenge_token_sequence = netcode_read_uint64(*cursor);
                netcode_read_bytes(*cursor, packet.challenge_token_data);

                return packet, sequence;
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
                if decrypted_bytes != 8 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection keep alive packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_keep_alive_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection keep alive packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);

                packet.client_index = netcode_read_uint32(*cursor);
                packet.max_clients = netcode_read_uint32(*cursor);

                return packet, sequence;
            case NETCODE_CONNECTION_PAYLOAD_PACKET;
                if decrypted_bytes < 1 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection payload packet. payload is too small\n");
                    return null, 0;
                }

                if decrypted_bytes > NETCODE_MAX_PAYLOAD_BYTES {
                    netcode_log(.VERBOSE_ONLY, "ignored connection payload packet. payload is too large\n");
                    return null, 0;
                }

                packet := netcode_create_payload_packet(decrypted_bytes);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection payload packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);

                memcpy(packet.payload_data.data, cursor, decrypted_bytes);

                return packet, sequence;
            case NETCODE_CONNECTION_DISCONNECT_PACKET;
                if decrypted_bytes != 0 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection disconnect packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_disconnect_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection disconnect packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_DISCONNECT_PACKET);

                return packet, sequence;
            case;
                return null, 0;
        }
    }
}

// ----------------------------------------------------------------

netcode_connect_token_t :: struct  {
    version_info         : VerionInfoBuf;
    protocol_id          : u64;
    create_timestamp     : Apollo_Time;
    expire_timestamp     : Apollo_Time;
    nonce                : BigNonceBuf;
    private_data         : ConnectTokenPrivateDataBuf;
    timeout_seconds      : Apollo_Time;
    num_server_addresses : int;
    server_addresses     : [NETCODE_MAX_SERVERS_PER_CONNECT] netcode_address_t;
    client_to_server_key : EncryptionKeyBuf;
    server_to_client_key : EncryptionKeyBuf;
}

// buffer expected to be zero'd
netcode_write_connect_token :: (connect_token: *netcode_connect_token_t, buffer: ConnectTokenBuf) {
    assert(connect_token != null);

    start := buffer.data;
    cursor := start;

    netcode_write_bytes(*cursor, connect_token.version_info);
    netcode_write_uint64(*cursor, connect_token.protocol_id);
    netcode_write_uint64(*cursor, cast(u64) to_milliseconds(connect_token.create_timestamp));
    netcode_write_uint64(*cursor, cast(u64) to_milliseconds(connect_token.expire_timestamp));
    netcode_write_bytes(*cursor, connect_token.nonce);
    netcode_write_bytes(*cursor, connect_token.private_data);
    // NOTE(dlb): no_check because -1 means "no timeout" and it's not a valid unsigned value bounds-wise
    netcode_write_uint32(*cursor, cast,no_check(u32) to_milliseconds(connect_token.timeout_seconds));
    netcode_write_uint32(*cursor, cast(u32) connect_token.num_server_addresses);

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];

        if address.type == NETCODE_ADDRESS_IPV4 {
            netcode_write_uint8(*cursor, NETCODE_ADDRESS_IPV4);
            for it_byte: 0..3 {
                netcode_write_uint8(*cursor, address.data.ipv4[it_byte]);
            }
            netcode_write_uint16(*cursor, address.port);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            netcode_write_uint8(*cursor, NETCODE_ADDRESS_IPV6);
            for it_byte: 0..7 {
                netcode_write_uint16(*cursor, address.data.ipv6[it_byte]);
            }
            netcode_write_uint16(*cursor, address.port);
        } else {
            assert(false, "Invalid address type");
        }
    }

    netcode_write_bytes(*cursor, connect_token.client_to_server_key);
    netcode_write_bytes(*cursor, connect_token.server_to_client_key);

    assert(pointer_diff(cursor, start) <= NETCODE_CONNECT_TOKEN_BYTES);
}

netcode_read_connect_token :: (buffer: ConnectTokenBuf, connect_token: *netcode_connect_token_t) -> int {
    assert(buffer.count > 0);
    assert(connect_token != null);

    cursor := buffer.data;

    netcode_read_bytes(*cursor, connect_token.version_info);
    if connect_token.version_info[0]  != #char "N" ||
       connect_token.version_info[1]  != #char "E" ||
       connect_token.version_info[2]  != #char "T" ||
       connect_token.version_info[3]  != #char "C" ||
       connect_token.version_info[4]  != #char "O" ||
       connect_token.version_info[5]  != #char "D" ||
       connect_token.version_info[6]  != #char "E" ||
       connect_token.version_info[7]  != #char " " ||
       connect_token.version_info[8]  != #char "1" ||
       connect_token.version_info[9]  != #char "." ||
       connect_token.version_info[10] != #char "0" ||
       connect_token.version_info[11] != #char "2" ||
       connect_token.version_info[12] != #char "\0"
    {
        connect_token.version_info[12] = #char "\0";
        netcode_log(.ERROR, "error: read connect data has bad version info (got %, expected %)\n", connect_token.version_info, NETCODE_VERSION_INFO);
        return NETCODE_ERROR;
    }

    connect_token.protocol_id = netcode_read_uint64(*cursor);
    connect_token.create_timestamp = milliseconds_to_apollo(cast(s64) netcode_read_uint64(*cursor));
    connect_token.expire_timestamp = milliseconds_to_apollo(cast(s64) netcode_read_uint64(*cursor));

    if connect_token.create_timestamp > connect_token.expire_timestamp {
        return NETCODE_ERROR;
    }

    netcode_read_bytes(*cursor, connect_token.nonce);
    netcode_read_bytes(*cursor, connect_token.private_data);

    connect_token.timeout_seconds = milliseconds_to_apollo(netcode_read_uint32(*cursor));
    connect_token.num_server_addresses = netcode_read_uint32(*cursor);

    if connect_token.num_server_addresses <= 0 || connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT {
        netcode_log(.ERROR, "error: read connect data has bad number of server addresses (%)\n", connect_token.num_server_addresses);
        return NETCODE_ERROR;
    }

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];

        address.type = netcode_read_uint8(*cursor);
        if address.type == NETCODE_ADDRESS_IPV4 {
            for it_byte: 0..3 {
                address.data.ipv4[it_byte] = netcode_read_uint8(*cursor);
            }
            address.port = netcode_read_uint16(*cursor);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            for it_byte: 0..7 {
                address.data.ipv6[it_byte] = netcode_read_uint16(*cursor);
            }
            address.port = netcode_read_uint16(*cursor);
        } else {
            netcode_log(.ERROR, "error: read connect data has bad address type (%)\n", address.type);
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes(*cursor, connect_token.client_to_server_key);
    netcode_read_bytes(*cursor, connect_token.server_to_client_key);

    return NETCODE_OK;
}

// ----------------------------------------------------------------

netcode_packet_queue_t :: struct {
    num_packets     : int;
    start_index     : int;
    packet_data     : [NETCODE_PACKET_QUEUE_SIZE] *netcode_connection_packet_t;
    packet_sequence : [NETCODE_PACKET_QUEUE_SIZE] u64;
}

netcode_packet_queue_clear :: (using queue: *netcode_packet_queue_t) {
    assert(queue != null);

    for 0..num_packets-1 {
        free(packet_data[it]);
    }
    queue.* = .{};
}

netcode_packet_queue_push :: (using queue: *netcode_packet_queue_t, packet: *netcode_connection_packet_t, sequence: u64) -> bool {
    assert(queue != null);
    assert(packet != null);

    if num_packets == NETCODE_PACKET_QUEUE_SIZE {
        free(packet);
        return false;
    }

    index := (start_index + num_packets) % NETCODE_PACKET_QUEUE_SIZE;
    packet_data[index] = packet;
    packet_sequence[index] = sequence;
    num_packets += 1;
    return true;
}

netcode_packet_queue_pop :: (using queue: *netcode_packet_queue_t) -> packet: *netcode_connection_packet_t, sequence: u64 {
    if num_packets == 0 {
        return null, 0;
    }

    packet := packet_data[start_index];
    sequence := packet_sequence[start_index];
    start_index = (start_index + 1) % NETCODE_PACKET_QUEUE_SIZE;
    num_packets -= 1;
    return packet, sequence;
}

// ----------------------------------------------------------------

NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES          :: NETCODE_MAX_CLIENTS * 256;
NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS :: NETCODE_MAX_CLIENTS * 64;

/*
Generate a random float between a and b.
IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
@param a The minimum integer value to generate.
@param b The maximum integer value to generate.
@returns A pseudo random float value in [a,b].
*/
netcode_random_float :: inline (a: float, b: float) -> float {
    assert(a < b);
    result := a + random_get_zero_to_one_new() * (b - a);
    assert(result >= a);
    assert(result <= b);
    return cast(float) result;
}

netcode_network_simulator_packet_entry_t :: struct {
    from          : netcode_address_t;
    to            : netcode_address_t;
    delivery_time : Apollo_Time;
    packet_data   : [] u8;
}

netcode_network_simulator_reset :: (using network_simulator: *netcode_network_simulator_t) {
    assert(network_simulator != null);

    netcode_log(.VERBOSE_ONLY, "network simulator reset\n");

    for * packet_entries {
        array_free(it.packet_data);
    }
    array_zero(packet_entries);

    for 0..num_pending_receive_packets-1 {
        array_free(pending_receive_packets[it].packet_data);
    }
    array_zero(pending_receive_packets);

    network_simulator.* = .{};
}

netcode_network_simulator_destroy :: (network_simulator: *netcode_network_simulator_t) {
    assert(network_simulator != null);

    netcode_network_simulator_reset(network_simulator);
    free(network_simulator);
}

netcode_network_simulator_queue_packet :: (using network_simulator: *netcode_network_simulator_t, from: netcode_address_t, to: netcode_address_t, packet_data: [] u8, delay: Apollo_Time) {
    entry := *packet_entries[current_index];
    entry.from = from;
    entry.to = to;
    entry.packet_data = array_copy(packet_data);
    entry.delivery_time = time + delay;

    current_index = (current_index + 1) % NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

netcode_network_simulator_send_packet :: (using network_simulator: *netcode_network_simulator_t, from: netcode_address_t, to: netcode_address_t, packet_data: [] u8) {
    assert(network_simulator != null);
    assert(from.type != 0);
    assert(to.type != 0);
    assert(packet_data.count > 0);
    assert(packet_data.count <= NETCODE_MAX_PACKET_BYTES);

    if netcode_random_float(0.0, 100.0) <= packet_loss_percent {
        return;
    }

    entry := *packet_entries[current_index];
    if entry.packet_data.count > 0 {
        array_reset(*entry.packet_data);
    }

    delay_ms := latency_milliseconds;

    if jitter_milliseconds > 0.0 {
        delay_ms += netcode_random_float(-jitter_milliseconds, jitter_milliseconds);
    }

    delay_time := milliseconds_to_apollo(cast(s64) delay_ms);
    netcode_network_simulator_queue_packet(network_simulator, from, to, packet_data, delay_time);

    if netcode_random_float(0.0, 100.0) <= duplicate_packet_percent {
        duplicate_jitter_time := milliseconds_to_apollo(cast(s64) netcode_random_float(0, 1000));
        netcode_network_simulator_queue_packet(network_simulator, from, to, packet_data, delay_time + duplicate_jitter_time);
    }
}

netcode_network_simulator_receive_packets :: (using network_simulator: *netcode_network_simulator_t, to: netcode_address_t, max_packets: int, packet_bufs: [][] u8, from: [] netcode_address_t) -> int {
    assert(network_simulator != null);
    assert(max_packets >= 0);
    assert(packet_bufs.count >= max_packets);
    assert(from.count >= max_packets);

    num_packets := 0;

    for 0..num_pending_receive_packets-1 {
        if num_packets == max_packets {
            break;
        }

        if pending_receive_packets[it].packet_data.count == 0 {
            continue;
        }

        if !netcode_address_equal(pending_receive_packets[it].to, to) {
            continue;
        }

        packet_bufs[num_packets] = pending_receive_packets[it].packet_data;
        from[num_packets] = pending_receive_packets[it].from;
        pending_receive_packets[it].packet_data = .{};  // memory ownerships transferred to packet_bufs

        num_packets += 1;
    }

    assert(num_packets <= max_packets);

    return num_packets;
}

netcode_network_simulator_update :: (using network_simulator: *netcode_network_simulator_t, _time: Apollo_Time) {
    assert(network_simulator != null);

    time = _time;

    // discard any pending receive packets that are still in the buffer

    for 0..num_pending_receive_packets-1 {
        packet := *pending_receive_packets[it];
        if packet.packet_data.count > 0 {
            array_reset(*packet.packet_data);
        }
    }

    num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for 0..NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES-1 {
        if num_pending_receive_packets == NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS {
            break;
        }

        packet := *packet_entries[it];
        if packet.packet_data.count == 0 {
            continue;
        }

        if packet.delivery_time <= time {
            pending_receive_packets[num_pending_receive_packets] = packet;
            num_pending_receive_packets += 1;
            packet.packet_data = .{};  // memory ownership transferred to pending queue
        }
    }
}

// TODO(dlb): We don't necessarily need this in Jai, but I'm too lazy to refactor it to an enum right now.
netcode_client_state_name :: (client_state: int) -> string {
    if client_state == {
        case NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED;                return "connect token expired";
        case NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN;                return "invalid connect token";
        case NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT;                 return "connection timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT;         return "connection request timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT;        return "connection response timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_DENIED;                    return "connection denied";
        case NETCODE_CLIENT_STATE_DISCONNECTED;                         return "disconnected";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST;           return "sending connection request";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE;          return "sending connection response";
        case NETCODE_CLIENT_STATE_CONNECTED;                            return "connected";
        case;
            assert(false, "unknown client state");
            return "<unknown client state>";
    }
}

netcode_client_socket_create :: (socket: *netcode_socket_t, address: netcode_address_t, send_buffer_size: s32, receive_buffer_size: s32, config: netcode_client_config_t) -> bool {
    assert(socket != null);

    if config.network_simulator == null {
        if !config.override_send_and_receive {
            if netcode_socket_create(socket, address, send_buffer_size, receive_buffer_size) != NETCODE_SOCKET_ERROR_NONE {
                return false;
            }
        }
    } else {
        if address.port == 0 {
            netcode_log(.ERROR, "error: must bind to a specific port when using network simulator\n");
            return false;
        }
    }

    return true;
}

// TODO(dlb): Rename this to netcode_client_create2
netcode_client_create_overload :: (address1_string: string, address2_string: string, config: netcode_client_config_t, time: Apollo_Time) -> *netcode_client_t {
    assert(netcode.initialized);

    address1: netcode_address_t;
    address2: netcode_address_t;

    if netcode_parse_address(address1_string, *address1) != NETCODE_OK {
        netcode_log(.ERROR, "error: failed to parse client address\n");
        return null;
    }

    if address2_string.count > 0 && netcode_parse_address(address2_string, *address2) != NETCODE_OK {
        netcode_log(.ERROR, "error: failed to parse client address2\n");
        return null;
    }


    socket_ipv4: netcode_socket_t;
    socket_ipv6: netcode_socket_t;

    if address1.type == NETCODE_ADDRESS_IPV4 || address2.type == NETCODE_ADDRESS_IPV4 {
        if !netcode_client_socket_create(*socket_ipv4, ifx address1.type == NETCODE_ADDRESS_IPV4 then *address1 else *address2, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE, config) {
            return null;
        }
    }

    if address1.type == NETCODE_ADDRESS_IPV6 || address2.type == NETCODE_ADDRESS_IPV6 {
        if !netcode_client_socket_create(*socket_ipv6, ifx address1.type == NETCODE_ADDRESS_IPV6 then *address1 else *address2, NETCODE_CLIENT_SOCKET_SNDBUF_SIZE, NETCODE_CLIENT_SOCKET_RCVBUF_SIZE, config) {
            return null;
        }
    }

    client := New(netcode_client_t);
    if client == null {
        netcode_socket_destroy(*socket_ipv4);
        netcode_socket_destroy(*socket_ipv6);
        return null;
    }

    socket_address := ifx address1.type == NETCODE_ADDRESS_IPV4 then socket_ipv4.address else socket_ipv6.address;
    if !config.network_simulator {
        netcode_log(.VERBOSE_ONLY, "client started on port %\n", socket_address.port);
    } else {
        netcode_log(.VERBOSE_ONLY, "client started on port % (network simulator)\n", socket_address.port);
    }

    client.config = config;
    client.socket_holder.ipv4 = socket_ipv4;
    client.socket_holder.ipv6 = socket_ipv6;
    client.address = ifx config.network_simulator then address1 else socket_address;
    client.state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client.time = time;
    client.last_packet_send_time = seconds_to_apollo(-1000);
    client.last_packet_receive_time = seconds_to_apollo(-1000);
    client.should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;

    netcode_replay_protection_reset(*client.replay_protection);

    return client;
}

netcode_client_set_state :: (using client: *netcode_client_t, client_state: int) {
    netcode_log(.VERY_VERBOSE_ONLY, "client changed state from '%' to '%'\n", netcode_client_state_name(state), netcode_client_state_name(client_state));

    if config.state_change_callback != null {
        config.state_change_callback(config.callback_context, state, client_state);
    }

    state = client_state;
}

netcode_client_reset_before_next_connect :: (using client: *netcode_client_t) {
    connect_start_time = time;
    last_packet_send_time = time - seconds_to_apollo(1);
    last_packet_receive_time = time;
    should_disconnect = false;
    should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    challenge_token_sequence = 0;

    array_zero(challenge_token_data);

    netcode_replay_protection_reset(*replay_protection);
}

netcode_client_reset_connection_data :: (using client: *netcode_client_t, client_state: int) {
    assert(client != null);

    sequence = 0;
    loopback = false;
    client_index = 0;
    max_clients = 0;
    connect_start_time = .{};
    server_address_index = 0;
    server_address = .{};
    connect_token = .{};
    ctx = .{};

    netcode_client_set_state(client, client_state);

    netcode_client_reset_before_next_connect(client);

    while true {
        packet := netcode_packet_queue_pop(*packet_receive_queue);
        if packet == null {
            break;
        }
        free(packet);
    }

    netcode_packet_queue_clear(*packet_receive_queue);
}

netcode_client_process_packet_internal :: (using client: *netcode_client_t, from: netcode_address_t, packet: *netcode_connection_packet_t, packet_sequence: u64) {
    assert(client != null);
    assert(packet != null);

    if packet.type == {
        case NETCODE_CONNECTION_DENIED_PACKET;
            if (state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST || state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE) && netcode_address_equal(from, server_address) {
                should_disconnect = true;
                should_disconnect_state = NETCODE_CLIENT_STATE_CONNECTION_DENIED;
                last_packet_receive_time = time;
            }
        case NETCODE_CONNECTION_CHALLENGE_PACKET;
            if state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST && netcode_address_equal(from, server_address) {
                netcode_log(.VERY_VERBOSE_ONLY, "client received connection challenge packet from server\n");

                p := cast(*netcode_connection_challenge_packet_t) packet;
                challenge_token_sequence = p.challenge_token_sequence;
                challenge_token_data = p.challenge_token_data;
                last_packet_receive_time = time;

                netcode_client_set_state(client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE);
            }
        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            if netcode_address_equal(from, server_address) {
                p := cast(*netcode_connection_keep_alive_packet_t) packet;

                if state == NETCODE_CLIENT_STATE_CONNECTED {
                    netcode_log(.VERY_VERBOSE_ONLY, "client received connection keep alive packet from server\n");

                    last_packet_receive_time = time;
                } else if state == NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE {
                    netcode_log(.VERY_VERBOSE_ONLY, "client received connection keep alive packet from server\n");

                    last_packet_receive_time = time;
                    client_index = p.client_index;
                    max_clients = p.max_clients;

                    netcode_client_set_state(client, NETCODE_CLIENT_STATE_CONNECTED);

                    netcode_log(.VERBOSE_ONLY, "client connected to server\n");
                }
            }
        case NETCODE_CONNECTION_PAYLOAD_PACKET;
            if state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal(from, server_address) {
                netcode_log(.VERY_VERBOSE_ONLY, "client received connection payload packet from server\n");

                netcode_packet_queue_push(*packet_receive_queue, packet, packet_sequence);

                last_packet_receive_time = time;

                return;
            }
        case NETCODE_CONNECTION_DISCONNECT_PACKET;
            if state == NETCODE_CLIENT_STATE_CONNECTED && netcode_address_equal(from, server_address) {
                netcode_log(.VERY_VERBOSE_ONLY, "client received disconnect packet from server\n");

                should_disconnect = true;
                should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
                last_packet_receive_time = time;
            }
    }

    free(packet);
}

netcode_client_receive_packets :: (using client: *netcode_client_t) {
    assert(client != null);
    assert(!loopback);

    allowed_packets: AllowedPacketsBuf;
    allowed_packets[NETCODE_CONNECTION_DENIED_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_CHALLENGE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = true;

    current_timestamp := current_time_monotonic();

    if !config.network_simulator {
        // process packets received from socket

        while true {
            from: netcode_address_t;
            packet_buf: [NETCODE_MAX_PACKET_BYTES] u8;
            packet_bytes := 0;

            if config.override_send_and_receive {
                assert(config.receive_packet_override != null);
                packet_bytes = config.receive_packet_override(config.callback_context, *from, packet_buf);
            } else if server_address.type == NETCODE_ADDRESS_IPV4 {
                packet_bytes = netcode_socket_receive_packet(socket_holder.ipv4, *from, packet_buf);
            } else if server_address.type == NETCODE_ADDRESS_IPV6 {
                packet_bytes = netcode_socket_receive_packet(socket_holder.ipv6, *from, packet_buf);
            }

            if packet_bytes == 0 {
                break;
            }

            packet, sequence := netcode_read_packet(
                .{ packet_bytes, packet_buf.data },
                ctx.read_packet_key,
                connect_token.protocol_id,
                current_timestamp,
                null,
                allowed_packets,
                *replay_protection,
            );

            if packet == null {
                continue;
            }

            netcode_client_process_packet_internal(client, *from, packet, sequence);
        }
    } else {
        // process packets received from network simulator

        num_packets_received := netcode_network_simulator_receive_packets(
            config.network_simulator,
            *address,
            NETCODE_CLIENT_MAX_RECEIVE_PACKETS,
            receive_packet_data,
            receive_from
        );

        for 0..num_packets_received-1 {
            packet, sequence := netcode_read_packet(
                receive_packet_data[it],
                ctx.read_packet_key,
                connect_token.protocol_id,
                current_timestamp,
                null,
                allowed_packets,
                *replay_protection,
            );

            array_reset(*receive_packet_data[it]);

            if packet == null {
                continue;
            }

            netcode_client_process_packet_internal(client, *receive_from[it], packet, sequence);
        }
    }
}

netcode_client_send_packet_to_server_internal :: (using client: *netcode_client_t, packet: *netcode_connection_packet_t) {
    assert(client != null);
    assert(packet != null);
    assert(!loopback);

    packet_buf: [NETCODE_MAX_PACKET_BYTES] u8;
    packet_bytes := netcode_write_packet(
        packet,
        packet_buf,
        sequence,
        ctx.write_packet_key,
        connect_token.protocol_id
    );
    sequence += 1;

    assert(packet_bytes <= NETCODE_MAX_PACKET_BYTES);
    packet_data: [] u8 = .{ packet_bytes, packet_buf.data };

    if config.network_simulator {
        netcode_network_simulator_send_packet(config.network_simulator, address, server_address, packet_data);
    } else {
        if config.override_send_and_receive {
            assert(config.send_packet_override != null);
            config.send_packet_override(config.callback_context, server_address, packet_data);
        } else if server_address.type == NETCODE_ADDRESS_IPV4 {
            netcode_socket_send_packet(socket_holder.ipv4, server_address, packet_data);
        } else if server_address.type == NETCODE_ADDRESS_IPV6 {
            netcode_socket_send_packet(socket_holder.ipv6, server_address, packet_data);
        }
    }

    last_packet_send_time = time;
}

netcode_client_send_packets :: (using client: *netcode_client_t) {
    assert(client != null);
    assert(!loopback);

    if time <= last_packet_send_time + milliseconds_to_apollo(1000 / NETCODE_PACKET_SEND_RATE) {
        return;
    }

    if state == {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST;
            netcode_log(.VERY_VERBOSE_ONLY, "client sent connection request packet to server\n");

            packet: netcode_connection_request_packet_t;
            assert(packet.type == NETCODE_CONNECTION_REQUEST_PACKET);
            packet.version_info = NETCODE_VERSION_INFO;
            packet.protocol_id = connect_token.protocol_id;
            packet.connect_token_expire_timestamp = connect_token.expire_timestamp;
            packet.connect_token_nonce = connect_token.nonce;
            packet.connect_token_data = connect_token.private_data;

            netcode_client_send_packet_to_server_internal(client, *packet);
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE;
            netcode_log(.VERY_VERBOSE_ONLY, "client sent connection response packet to server\n");

            packet: netcode_connection_response_packet_t;
            assert(packet.type == NETCODE_CONNECTION_RESPONSE_PACKET);
            packet.challenge_token_sequence = challenge_token_sequence;
            packet.challenge_token_data = challenge_token_data;

            netcode_client_send_packet_to_server_internal(client, *packet);
        case NETCODE_CLIENT_STATE_CONNECTED;
            netcode_log(.VERY_VERBOSE_ONLY, "client sent connection keep-alive packet to server\n");

            packet: netcode_connection_keep_alive_packet_t;
            assert(packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
            packet.client_index = 0;
            packet.max_clients = 0;

            netcode_client_send_packet_to_server_internal(client, *packet);
    }
}

netcode_client_connect_to_next_server :: (using client: *netcode_client_t) -> bool {
    assert(client != null);

    if server_address_index + 1 >= connect_token.num_server_addresses {
        netcode_log(.VERY_VERBOSE_ONLY, "client has no more servers to connect to\n");
        return false;
    }

    server_address_index += 1;
    server_address = connect_token.server_addresses[server_address_index];

    netcode_client_reset_before_next_connect(client);

    netcode_log(.VERBOSE_ONLY, "client connecting to next server % [%/%]\n",
        netcode_address_to_string(*server_address,, temp),
        server_address_index + 1,
        connect_token.num_server_addresses
    );

    netcode_client_set_state(client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST);

    return true;
}

netcode_client_disconnect_internal :: (using client: *netcode_client_t, destination_state: int, send_disconnect_packets: bool) {
    assert(!loopback);
    assert(destination_state <= NETCODE_CLIENT_STATE_DISCONNECTED);

    if state <= NETCODE_CLIENT_STATE_DISCONNECTED || state == destination_state {
        return;
    }

    netcode_log(.VERBOSE_ONLY, "client disconnected\n");

    if !loopback && send_disconnect_packets && state > NETCODE_CLIENT_STATE_DISCONNECTED {
        netcode_log(.VERY_VERBOSE_ONLY, "client sent disconnect packets to server\n");

        for 0..NETCODE_NUM_DISCONNECT_PACKETS-1 {
            netcode_log(.VERY_VERBOSE_ONLY, "client sent disconnect packet %\n", it);

            packet: netcode_connection_disconnect_packet_t;
            assert(packet.type == NETCODE_CONNECTION_DISCONNECT_PACKET);
            netcode_client_send_packet_to_server_internal(client, *packet);
        }
    }

    netcode_client_reset_connection_data(client, destination_state);
}

// ----------------------------------------------------------------

NETCODE_MAX_ENCRYPTION_MAPPINGS :: NETCODE_MAX_CLIENTS * 4;

netcode_encryption_manager_t :: struct {
    num_encryption_mappings : int;
    timeout                 : [NETCODE_MAX_ENCRYPTION_MAPPINGS] Apollo_Time;
    expire_time             : [NETCODE_MAX_ENCRYPTION_MAPPINGS] Apollo_Time;
    last_access_time        : [NETCODE_MAX_ENCRYPTION_MAPPINGS] Apollo_Time;
    address                 : [NETCODE_MAX_ENCRYPTION_MAPPINGS] netcode_address_t;
    client_index            : [NETCODE_MAX_ENCRYPTION_MAPPINGS] int;
    send_key                : [NETCODE_MAX_ENCRYPTION_MAPPINGS] EncryptionKeyBuf;
    receive_key             : [NETCODE_MAX_ENCRYPTION_MAPPINGS] EncryptionKeyBuf;
}

netcode_encryption_manager_reset :: (using encryption_manager: *netcode_encryption_manager_t) {
    netcode_log(.VERY_VERBOSE_ONLY, "reset encryption manager\n");

    assert(encryption_manager != null);

    num_encryption_mappings = 0;

    for 0..NETCODE_MAX_ENCRYPTION_MAPPINGS-1 {
        // NOTE(dlb): These are some weird "null" values.. I'm not sure if I interpreted the original code correctly but it should be fine.
        expire_time[it] = APOLLO_TIME_INVALID;
        last_access_time[it] = seconds_to_apollo(-1000);
        address[it] = .{};
        client_index[it] = -1;
    }

    array_zero(timeout);
    array_zero(send_key);
    array_zero(receive_key);
}

netcode_encryption_manager_entry_expired :: (using encryption_manager: netcode_encryption_manager_t, index: int, time: Apollo_Time) -> bool {
    return (timeout[index] > .{} && (last_access_time[index] + timeout[index]) < time)
        || (expire_time[index] >= .{} && expire_time[index] < time);
}

netcode_encryption_manager_add_encryption_mapping :: (
    using encryption_manager: *netcode_encryption_manager_t,
    _address: netcode_address_t,
    _send_key: EncryptionKeyBuf,
    _receive_key: EncryptionKeyBuf,
    _time: Apollo_Time,
    _expire_time: Apollo_Time,
    _timeout: Apollo_Time
) -> bool {
    for 0..num_encryption_mappings-1 {
        if netcode_address_equal(address[it], _address) && !netcode_encryption_manager_entry_expired(encryption_manager, it, _time) {
            timeout[it] = _timeout;
            expire_time[it] = _expire_time;
            last_access_time[it] = _time;
            array_copy(send_key[it], _send_key);
            array_copy(receive_key[it], _receive_key);
            return true;
        }
    }

    for 0..NETCODE_MAX_ENCRYPTION_MAPPINGS-1 {
        if address[it].type == NETCODE_ADDRESS_NONE || (netcode_encryption_manager_entry_expired(encryption_manager, it, _time) && client_index[it] == -1) {
            timeout[it] = _timeout;
            expire_time[it] = _expire_time;
            last_access_time[it] = _time;
            address[it] = _address;
            array_copy(send_key[it], _send_key);
            array_copy(receive_key[it], _receive_key);
            if it >= num_encryption_mappings {
                num_encryption_mappings = it + 1;
            }
            return true;
        }
    }

    return false;
}

netcode_encryption_manager_remove_encryption_mapping :: (using encryption_manager: *netcode_encryption_manager_t, _address: netcode_address_t, time: Apollo_Time) -> bool {
    assert(encryption_manager != null);

    for 0..num_encryption_mappings-1 {
        if netcode_address_equal(address[it], _address) {
            expire_time[it] = APOLLO_TIME_INVALID;
            last_access_time[it] = seconds_to_apollo(-1000);
            address[it] = .{};
            array_zero(send_key[it]);
            array_zero(receive_key[it]);

            if it == num_encryption_mappings - 1 {
                index := it - 1;
                while index >= 0 {
                    if !netcode_encryption_manager_entry_expired(encryption_manager, index, time) || client_index[index] != -1 {
                        break;
                    }
                    address[index].type = NETCODE_ADDRESS_NONE;
                    index -= 1;
                }
                num_encryption_mappings = index + 1;
            }

            return true;
        }
    }

    return false;
}

netcode_encryption_manager_find_encryption_mapping :: (using encryption_manager: netcode_encryption_manager_t, _address: netcode_address_t, time: Apollo_Time) -> int {
    for 0..num_encryption_mappings-1 {
        if netcode_address_equal(address[it], _address) && !netcode_encryption_manager_entry_expired(encryption_manager, it, time) {
            last_access_time[it] = time;
            return it;
        }
    }
    return -1;
}

netcode_encryption_manager_touch :: (using encryption_manager: *netcode_encryption_manager_t, index: int, _address: netcode_address_t, time: Apollo_Time) -> bool {
    assert(index >= 0);
    assert(index < num_encryption_mappings);

    if !netcode_address_equal(address[index], _address) {
        return false;
    }
    last_access_time[index] = time;
    return true;
}

netcode_encryption_manager_set_expire_time :: (using encryption_manager: *netcode_encryption_manager_t, index: int, _expire_time: Apollo_Time) {
    assert(index >= 0);
    assert(index < num_encryption_mappings);

    expire_time[index] = _expire_time;
}

netcode_encryption_manager_get_send_key :: (using encryption_manager: netcode_encryption_manager_t, index: int) -> *EncryptionKeyBuf {
    assert(index >= -1);
    assert(index < num_encryption_mappings);

    if index == -1 {
        return null;
    }
    return *send_key[index];
}

netcode_encryption_manager_get_receive_key :: (using encryption_manager: netcode_encryption_manager_t, index: int) -> *EncryptionKeyBuf {
    assert(index >= -1);
    assert(index < num_encryption_mappings);

    if index == -1 {
        return null;
    }
    return *receive_key[index];
}

netcode_encryption_manager_get_timeout :: (using encryption_manager: netcode_encryption_manager_t, index: int) -> Apollo_Time {
    assert(index >= -1);
    assert(index < num_encryption_mappings);

    if index == -1 {
        return .{};
    }
    return timeout[index];
}

// ----------------------------------------------------------------

NETCODE_MAX_CONNECT_TOKEN_ENTRIES :: NETCODE_MAX_CLIENTS * 8;

netcode_connect_token_entry_t :: struct {
    time    : Apollo_Time;
    mac     : MacBuf;
    address : netcode_address_t;
}

netcode_connect_token_entries_reset :: (connect_token_entries: [NETCODE_MAX_CONNECT_TOKEN_ENTRIES] netcode_connect_token_entry_t) {
    for * connect_token_entries {
        it.time = seconds_to_apollo(-1000);
        array_zero(it.mac);
        it.address = .{};
    }
}

netcode_connect_token_entries_find_or_add :: (connect_token_entries: *[NETCODE_MAX_CONNECT_TOKEN_ENTRIES] netcode_connect_token_entry_t, address: netcode_address_t, mac: MacBuf, time: Apollo_Time) -> bool {
    // find the matching entry for the token mac and the oldest token entry. constant time worst case. This is intentional!

    matching_token_index := -1;
    oldest_token_index := -1;
    oldest_token_time: Apollo_Time;

    for * connect_token_entries.* {
        if array_equal(it.mac, mac) {
            matching_token_index = it_index;
        }

        if oldest_token_index == -1 || it.time < oldest_token_time {
            oldest_token_time = it.time;
            oldest_token_index = it_index;
        }
    }

    // if no entry is found with the mac, this is a new connect token. replace the oldest token entry.

    assert(oldest_token_index != -1);

    if matching_token_index == -1 {
        connect_token_entries.*[oldest_token_index].time = time;
        connect_token_entries.*[oldest_token_index].address = address;
        array_copy(connect_token_entries.*[oldest_token_index].mac, mac);
        return true;
    }

    // allow connect tokens we have already seen from the same address

    assert(matching_token_index >= 0);
    assert(matching_token_index < NETCODE_MAX_CONNECT_TOKEN_ENTRIES);
    if netcode_address_equal(connect_token_entries.*[matching_token_index].address, address) {
        return true;
    }

    return false;
}

//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
// Everything below this line should have the correct pointer vs. non-pointer semantics
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////
//////////////// POINTER VS. REFERENCE BOOKMARK //////////////////////////////

// ----------------------------------------------------------------

// TODO(dlb): This 'address_map' data structure is kinda silly, why is it even a bucket array? The pointers clearly don't need
// to be stable, otherwise _delete wouldn't swap the last element into the hole. We can probably just use Jai's Hash_Table here.

netcode_address_map_element_t :: struct {
    client_index : int;
    address      : netcode_address_t;
}

netcode_address_map_bucket_t :: struct {
    size     : int;
    elements : [NETCODE_MAX_CLIENTS] netcode_address_map_element_t;
}

netcode_address_map_t :: struct {
    size    : int;
    buckets : [NETCODE_ADDRESS_MAP_BUCKETS] netcode_address_map_bucket_t;
}

netcode_address_map_create :: () -> *netcode_address_map_t {
    map := New(netcode_address_map_t);
    assert(map != null);

    netcode_address_map_reset(map);
    return map;
}

// TODO(dlb)[cleanup] Seems like nobody even calls this.. useless function, clean it up?
netcode_address_map_destroy :: (map: *netcode_address_map_t) {
    assert(map != null);

    free(map);
}

netcode_fnv_t :: u64;

netcode_fnv_init :: (fnv: *netcode_fnv_t) {
    fnv.* = 0x_CBF2_9CE4_8422_2325;
}

netcode_fnv_write :: (fnv: *netcode_fnv_t, data: [] u8) {
    for data {
        fnv.* ^= it;
        fnv.* *= 0x_0000_0100_0000_01B3;
    }
}

netcode_fnv_finalize :: inline (fnv: *netcode_fnv_t) -> u64 {
    return fnv.*;
}

netcode_hash_string :: (str: string) -> u64 {
    fnv: netcode_fnv_t;
    netcode_fnv_init(*fnv);
    netcode_fnv_write(*fnv, str);
    return netcode_fnv_finalize(*fnv);
}

netcode_hash_data :: (data: [] u8) -> u64 {
    fnv: netcode_fnv_t;
    netcode_fnv_init(*fnv);
    netcode_fnv_write(*fnv, data);
    return netcode_fnv_finalize(*fnv);
}

netcode_address_hash :: (address: netcode_address_t) -> int {
    addr_bytes := [] u8.{ size_of(type_of(address)), cast(*u8) *address };
    hash := cast(int) (netcode_hash_data(addr_bytes) >> 1);
    return hash % NETCODE_ADDRESS_MAP_BUCKETS;
}

netcode_address_map_element_reset :: (using element: *netcode_address_map_element_t) {
    client_index = -1;
    address = .{};
}

netcode_address_map_bucket_reset :: (using bucket: *netcode_address_map_bucket_t) {
    size = 0;
    for * elements {
        netcode_address_map_element_reset(it);
    }
}

netcode_address_map_reset :: (using map: *netcode_address_map_t) {
    size = 0;
    for * buckets {
        netcode_address_map_bucket_reset(it);
    }
}

netcode_address_map_set :: (map: *netcode_address_map_t, address: netcode_address_t, client_index: int) -> bool {
    bucket_index := netcode_address_hash(address);
    bucket := *map.buckets[bucket_index];
    if bucket.size == NETCODE_MAX_CLIENTS {
        return false;
    }

    element := *bucket.elements[bucket.size];
    element.client_index = client_index;
    element.address = address;

    bucket.size += 1;
    map.size += 1;
    return true;
}

netcode_address_map_bucket_find :: (bucket: netcode_address_map_bucket_t, address: netcode_address_t) -> *netcode_address_map_element_t {
    for 0..bucket.size-1 {
        element := *bucket.elements[it];
        if netcode_address_equal(address, element.address) {
            return element;
        }
    }

    return null;
}

netcode_address_map_get :: (map: netcode_address_map_t, address: netcode_address_t) -> int {
    bucket_index := netcode_address_hash(address);
    bucket := map.buckets[bucket_index];
    element := netcode_address_map_bucket_find(bucket, address);

    if element == null {
        return -1;
    }

    return element.client_index;
}

netcode_address_map_delete :: (map: *netcode_address_map_t, address: netcode_address_t) -> bool {
    bucket_index := netcode_address_hash(address);
    bucket := *map.buckets[bucket_index];

    element := netcode_address_map_bucket_find(bucket, address);
    if element == null {
        return false;
    }

    last := *bucket.elements[bucket.size-1];
    if element != last {
        element.* = last.*;
    }
    netcode_address_map_element_reset(last);

    bucket.size -= 1;
    map.size -= 1;
    return true;
}

// ----------------------------------------------------------------

// TODO(dlb): Use enum_flags
NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS  :: 1;
NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS :: 1 << 1;

netcode_server_socket_create:: (socket: *netcode_socket_t, address: netcode_address_t, send_buffer_size: s32, receive_buffer_size: s32, config: netcode_server_config_t) -> bool {
    assert(socket != null);

    if config.network_simulator == null {
        if !config.override_send_and_receive {
            if netcode_socket_create(socket, address, send_buffer_size, receive_buffer_size) != NETCODE_SOCKET_ERROR_NONE {
                return false;
            }
        }
    }

    return true;
}

// TODO(dlb): Rename this to netcode_server_create2
// TODO(dlb): Make this take IPAddress instead of string, to remove the pointless double-parse in Yojimbo server_start()
netcode_server_create_overload :: (server_address1_string: string, server_address2_string: string, config: netcode_server_config_t, time: Apollo_Time) -> *netcode_server_t {
    assert(netcode.initialized);

    server_address1: netcode_address_t;
    server_address2: netcode_address_t;

    if netcode_parse_address(server_address1_string, *server_address1) != NETCODE_OK {
        netcode_log(.ERROR, "error: failed to parse server public address\n");
        return null;
    }

    if server_address2_string.count > 0 && netcode_parse_address(server_address2_string, *server_address2) != NETCODE_OK {
        netcode_log(.ERROR, "error: failed to parse server public address2\n");
        return null;
    }

    bind_address_ipv4: netcode_address_t;
    bind_address_ipv6: netcode_address_t;
    socket_ipv4: netcode_socket_t;
    socket_ipv6: netcode_socket_t;

    if server_address1.type == NETCODE_ADDRESS_IPV4 || server_address2.type == NETCODE_ADDRESS_IPV4 {
        bind_address_ipv4.type = NETCODE_ADDRESS_IPV4;
        bind_address_ipv4.port = ifx server_address1.type == NETCODE_ADDRESS_IPV4 then server_address1.port else server_address2.port;

        if !netcode_server_socket_create(*socket_ipv4, bind_address_ipv4, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config) {
            return null;
        }
    }

    if server_address1.type == NETCODE_ADDRESS_IPV6 || server_address2.type == NETCODE_ADDRESS_IPV6 {
        bind_address_ipv6.type = NETCODE_ADDRESS_IPV6;
        bind_address_ipv6.port = ifx server_address1.type == NETCODE_ADDRESS_IPV6 then server_address1.port else server_address2.port;

        if !netcode_server_socket_create(*socket_ipv6, bind_address_ipv6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config) {
            return null;
        }
    }

    server := New(netcode_server_t);
    if server == null {
        netcode_socket_destroy(*socket_ipv4);
        netcode_socket_destroy(*socket_ipv6);
        return null;
    }

    if config.network_simulator == null {
        netcode_log(.VERBOSE_ONLY, "server listening on %\n", server_address1_string);
    } else {
        netcode_log(.VERBOSE_ONLY, "server listening on % (network simulator)\n", server_address1_string);
    }

    server.config = config;
    server.socket_holder.ipv4 = socket_ipv4;
    server.socket_holder.ipv6 = socket_ipv6;
    server.address = server_address1;
    server.time = time;
    server.global_sequence = 1 << 63;
    for * server.client_encryption_index {
        it.* = -1;
    }
    for * server.client_replay_protection {
        netcode_replay_protection_reset(it);
    }
    netcode_address_map_reset(*server.client_address_map);
    netcode_connect_token_entries_reset(server.connect_token_entries);
    netcode_encryption_manager_reset(*server.encryption_manager);

    return server;
}

netcode_server_send_global_packet :: (using server: *netcode_server_t, packet: *netcode_connection_packet_t, to: netcode_address_t, packet_key: EncryptionKeyBuf) {
    assert(server != null);
    assert(packet != null);

    packet_buf: [NETCODE_MAX_PACKET_BYTES] u8;
    packet_bytes := netcode_write_packet(packet, packet_buf, global_sequence, packet_key, config.protocol_id);

    assert(packet_bytes <= NETCODE_MAX_PACKET_BYTES);
    packet_data: [] u8 = .{ packet_bytes, packet_buf.data };

    if config.network_simulator != null {
        netcode_network_simulator_send_packet(config.network_simulator, address, to, packet_data);
    } else {
        if config.override_send_and_receive {
            assert(config.send_packet_override != null);
            config.send_packet_override(config.callback_context, to, packet_data);
        } else if to.type == NETCODE_ADDRESS_IPV4 {
            netcode_socket_send_packet(socket_holder.ipv4, to, packet_data);
        } else if to.type == NETCODE_ADDRESS_IPV6 {
            netcode_socket_send_packet(socket_holder.ipv6, to, packet_data);
        }
    }

    global_sequence += 1;
}

netcode_server_send_client_packet :: (using server: *netcode_server_t, packet: *netcode_connection_packet_t, client_index: int) {
    assert(server != null);
    assert(packet != null);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(client_connected[client_index]);
    assert(!client_loopback[client_index]);

    packet_buf: [NETCODE_MAX_PACKET_BYTES] u8;

    if !netcode_encryption_manager_touch(*encryption_manager, client_encryption_index[client_index], client_address[client_index], time) {
        netcode_log(.ERROR, "error: encryption mapping is out of date for client %\n", client_index);
        return;
    }

    packet_key := netcode_encryption_manager_get_send_key(encryption_manager, client_encryption_index[client_index]);
    packet_bytes := netcode_write_packet(packet, packet_buf, client_sequence[client_index], packet_key.*, config.protocol_id);
    assert(packet_bytes <= NETCODE_MAX_PACKET_BYTES);
    packet_data: [] u8 = .{ packet_bytes, packet_buf.data };

    if config.network_simulator != null {
        netcode_network_simulator_send_packet(config.network_simulator, address, client_address[client_index], packet_data);
    } else {
        if config.override_send_and_receive {
            assert(config.send_packet_override != null);
            config.send_packet_override(config.callback_context, client_address[client_index], packet_data);
        } else {
            if client_address[client_index].type == NETCODE_ADDRESS_IPV4 {
                netcode_socket_send_packet(socket_holder.ipv4, client_address[client_index], packet_data);
            } else if client_address[client_index].type == NETCODE_ADDRESS_IPV6 {
                netcode_socket_send_packet(socket_holder.ipv6, client_address[client_index], packet_data);
            }
        }
    }

    client_sequence[client_index] += 1;
    client_last_packet_send_time[client_index] = time;
}

netcode_server_disconnect_client_internal :: (using server: *netcode_server_t, client_index: int, send_disconnect_packets: bool) {
    assert(server != null);
    assert(running);
    assert(client_index >= 0);
    assert(client_index < max_clients);
    assert(client_connected[client_index]);
    assert(!client_loopback[client_index]);
    assert(encryption_manager.client_index[client_encryption_index[client_index]] == client_index);
    assert(num_connected_clients > 0);

    netcode_log(.VERBOSE_ONLY, "server disconnected client %\n", client_index);

    if config.connect_disconnect_callback != null {
        config.connect_disconnect_callback(config.callback_context, client_index, false);
    }

    if send_disconnect_packets {
        netcode_log(.VERY_VERBOSE_ONLY, "server sent disconnect packets to client %\n", client_index);

        for 0..NETCODE_NUM_DISCONNECT_PACKETS-1 {
            netcode_log(.VERY_VERBOSE_ONLY, "server sent disconnect packet %\n", it);

            packet: netcode_connection_disconnect_packet_t;
            assert(packet.type == NETCODE_CONNECTION_DISCONNECT_PACKET);
            netcode_server_send_client_packet(server, *packet, client_index);
        }
    }

    while true {
        packet := netcode_packet_queue_pop(*client_packet_queue[client_index]);
        if packet == null {
            break;
        }
        free(packet);
    }

    netcode_packet_queue_clear(*client_packet_queue[client_index]);

    netcode_replay_protection_reset(*client_replay_protection[client_index]);

    encryption_manager.client_index[client_encryption_index[client_index]] = -1;

    netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, client_address[client_index], time);

    client_connected[client_index] = false;
    client_confirmed[client_index] = false;
    client_id[client_index] = 0;
    client_sequence[client_index] = 0;
    client_last_packet_send_time[client_index] = .{};
    client_last_packet_receive_time[client_index] = .{};
    netcode_address_map_delete(*client_address_map, client_address[client_index]);
    client_address[client_index] = .{};
    client_encryption_index[client_index] = -1;
    array_zero(client_user_data[client_index]);

    num_connected_clients -= 1;
}

netcode_server_find_client_index_by_id :: (using server: *netcode_server_t, _client_id: u64) -> int {
    assert(server != null);

    for 0..max_clients-1 {
        if client_connected[it] && client_id[it] == _client_id {
            return it;
        }
    }

    return -1;
}

netcode_server_find_client_index_by_address :: (using server: netcode_server_t, _address: netcode_address_t) -> int {
    if _address.type == 0 {
        return -1;
    }

    return netcode_address_map_get(client_address_map, _address);
}

netcode_server_process_connection_request_packet :: (using server: *netcode_server_t, from: netcode_address_t, packet: *netcode_connection_request_packet_t) {
    assert(server != null);
    assert(packet != null);

    connect_token_private: netcode_connect_token_private_t;
    if netcode_read_connect_token_private(packet.connect_token_data, *connect_token_private) != NETCODE_OK {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. failed to read connect token\n");
        return;
    }

    found_server_address := false;
    for 0..connect_token_private.num_server_addresses-1 {
        if netcode_address_equal(address, connect_token_private.server_addresses[it]) {
            found_server_address = true;
        }
    }
    if !found_server_address {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. server address not in connect token whitelist\n");
        return;
    }

    if netcode_server_find_client_index_by_address(server, from) != -1 {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. a client with this address is already connected\n");
        return;
    }

    if netcode_server_find_client_index_by_id(server, connect_token_private.client_id) != -1 {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. a client with this id is already connected\n");
        return;
    }

    // Retrieve MAC from end of connect token data
    mac := (cast(*MacBuf) (packet.connect_token_data.data + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES)).*;
    if !netcode_connect_token_entries_find_or_add(*connect_token_entries, from, mac, time) {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. connect token has already been used\n");
        return;
    }

    if num_connected_clients == max_clients {
        netcode_log(.VERY_VERBOSE_ONLY, "server denied connection request. server is full\n");

        p: netcode_connection_denied_packet_t;
        assert(p.type == NETCODE_CONNECTION_DENIED_PACKET);
        netcode_server_send_global_packet(server, *p, from, connect_token_private.server_to_client_key);
        return;
    }

    expire_time := ifx connect_token_private.timeout_seconds >= .{} then time + connect_token_private.timeout_seconds else APOLLO_TIME_INVALID;

    if !netcode_encryption_manager_add_encryption_mapping(*encryption_manager, from,
        connect_token_private.server_to_client_key, connect_token_private.client_to_server_key, time, expire_time,
        connect_token_private.timeout_seconds
    ) {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. failed to add encryption mapping\n");
        return;
    }

    challenge_token: netcode_challenge_token_t;
    challenge_token.client_id = connect_token_private.client_id;
    array_copy(challenge_token.user_data, connect_token_private.user_data);

    challenge_packet: netcode_connection_challenge_packet_t;
    assert(challenge_packet.type == NETCODE_CONNECTION_CHALLENGE_PACKET);
    challenge_packet.challenge_token_sequence = challenge_sequence;
    netcode_write_challenge_token(challenge_token, challenge_packet.challenge_token_data);
    if netcode_encrypt_challenge_token(challenge_packet.challenge_token_data, challenge_sequence, challenge_key) != NETCODE_OK {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. failed to encrypt challenge token\n");
        return;
    }

    challenge_sequence += 1;

    netcode_log(.VERY_VERBOSE_ONLY, "server sent connection challenge packet\n");

    netcode_server_send_global_packet(server, *challenge_packet, from, connect_token_private.server_to_client_key);
}

netcode_server_find_free_client_index :: (using server: netcode_server_t) -> int {
    for 0..max_clients-1 {
        if !client_connected[it] {
            return it;
        }
    }

    return -1;
}

netcode_server_connect_client :: (using server: *netcode_server_t, _client_index: int, _address: netcode_address_t, _client_id: u64, _encryption_index: int, _timeout_seconds: Apollo_Time, _user_data: UserDataBuf) {
    assert(server != null);
    assert(running);
    assert(_client_index >= 0);
    assert(_client_index < max_clients);
    assert(_encryption_index != -1);
    assert(encryption_manager.client_index[_encryption_index] == -1);
    assert(client_connected[_client_index] == false);
    assert(num_connected_clients < max_clients);

    netcode_encryption_manager_set_expire_time(*encryption_manager, _encryption_index, APOLLO_TIME_INVALID);

    encryption_manager.client_index[_encryption_index] = _client_index;

    client_connected[_client_index] = true;
    client_timeout[_client_index] = _timeout_seconds;
    client_encryption_index[_client_index] = _encryption_index;
    client_id[_client_index] = _client_id;
    client_sequence[_client_index] = 0;
    client_address[_client_index] = _address;
    netcode_address_map_set(*client_address_map, _address, _client_index);
    client_last_packet_send_time[_client_index] = time;
    client_last_packet_receive_time[_client_index] = time;
    array_copy(client_user_data[_client_index], _user_data);

    netcode_log(.VERBOSE_ONLY, "server accepted client % % in slot %\n", netcode_address_to_string(_address,, temp), _client_id, _client_index);

    packet: netcode_connection_keep_alive_packet_t;
    assert(packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
    packet.client_index = _client_index;
    packet.max_clients = max_clients;

    netcode_server_send_client_packet(server, *packet, _client_index);
    num_connected_clients += 1;

    if config.connect_disconnect_callback {
        config.connect_disconnect_callback(config.callback_context, _client_index, true);
    }
}

netcode_server_process_connection_response_packet :: (using server: *netcode_server_t, from: netcode_address_t, packet: *netcode_connection_response_packet_t, encryption_index: int) {
    assert(server != null);
    assert(packet != null);

    if netcode_decrypt_challenge_token(packet.challenge_token_data, packet.challenge_token_sequence, challenge_key) != NETCODE_OK {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. failed to decrypt challenge token\n");
        return;
    }

    challenge_token: netcode_challenge_token_t;
    if netcode_read_challenge_token(packet.challenge_token_data, *challenge_token) != NETCODE_OK {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. failed to read challenge token\n");
        return;
    }

    packet_send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
    if packet_send_key == null {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. no packet send key\n");
        return;
    }

    if netcode_server_find_client_index_by_address(server, from) != -1 {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. a client with this address is already connected\n");
        return;
    }

    if netcode_server_find_client_index_by_id(server, challenge_token.client_id) != -1 {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. a client with this id is already connected\n");
        return;
    }

    if num_connected_clients == max_clients {
        netcode_log(.VERY_VERBOSE_ONLY, "server denied connection response. server is full\n");

        p: netcode_connection_denied_packet_t;
        assert(p.type == NETCODE_CONNECTION_DENIED_PACKET);
        netcode_server_send_global_packet(server, *p, from, packet_send_key.*);
        return;
    }

    client_index := netcode_server_find_free_client_index(server);
    assert(client_index != -1);

    timeout_seconds := netcode_encryption_manager_get_timeout(*encryption_manager, encryption_index);

    netcode_server_connect_client(server, client_index, from, challenge_token.client_id, encryption_index, timeout_seconds, challenge_token.user_data);
}

netcode_server_process_packet_internal :: (using server: *netcode_server_t, from: netcode_address_t, packet: *netcode_connection_packet_t, sequence: u64, encryption_index: int, client_index: int) {
    assert(server != null);
    assert(packet != null);

    if packet.type == {
        case NETCODE_CONNECTION_REQUEST_PACKET;
            if !(flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS) {
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection request from %\n", netcode_address_to_string(from,, temp));
                p := cast(*netcode_connection_request_packet_t) packet;
                netcode_server_process_connection_request_packet(server, from, p);
            }
        case NETCODE_CONNECTION_RESPONSE_PACKET;
            if !(flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS) {
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection response from %\n", netcode_address_to_string(from,, temp));
                p := cast(*netcode_connection_response_packet_t) packet;
                netcode_server_process_connection_response_packet(server, from, p, encryption_index);
            }
        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            if client_index != -1 {
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection keep alive packet from client %\n", client_index);
                client_last_packet_receive_time[client_index] = time;
                if !client_confirmed[client_index] {
                    netcode_log(.VERY_VERBOSE_ONLY, "server confirmed connection with client %\n", client_index);
                    client_confirmed[client_index] = true;
                }
            }
        case NETCODE_CONNECTION_PAYLOAD_PACKET;
            if client_index != -1 {
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection payload packet from client %\n", client_index);
                client_last_packet_receive_time[client_index] = time;
                if !client_confirmed[client_index] {
                    netcode_log(.VERY_VERBOSE_ONLY, "server confirmed connection with client %\n", client_index);
                    client_confirmed[client_index] = true;
                }
                netcode_packet_queue_push(*client_packet_queue[client_index], packet, sequence);
                return;
            }
        case NETCODE_CONNECTION_DISCONNECT_PACKET;
            if client_index != -1 {
                netcode_log(.VERY_VERBOSE_ONLY, "server received disconnect packet from client %\n", client_index);
                netcode_server_disconnect_client_internal(server, client_index, false);
           }
    }

    free(packet);
}

netcode_server_read_and_process_packet :: (using server: *netcode_server_t, from: netcode_address_t, packet_data: [] u8, current_timestamp: Apollo_Time, allowed_packets: AllowedPacketsBuf) {
    if !running {
        return;
    }
    if packet_data.count == 0 {
        return;
    }

    encryption_index := -1;
    client_index := netcode_server_find_client_index_by_address(server, from);
    if client_index != -1 {
        assert(client_index >= 0);
        assert(client_index < max_clients);
        encryption_index = client_encryption_index[client_index];
    } else {
        encryption_index = netcode_encryption_manager_find_encryption_mapping(*encryption_manager, from, time);
    }

    read_packet_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);
    if read_packet_key == null && packet_data[0] != 0 {
        netcode_log(.VERY_VERBOSE_ONLY, "server could not process packet (type %) because no encryption mapping exists for %\n", packet_data[0] & 0xF, netcode_address_to_string(from,, temp));
        return;
    }

    packet, sequence := netcode_read_packet(
        packet_data,
        read_packet_key.*,
        config.protocol_id,
        current_timestamp,
        *config.private_key,
        allowed_packets,
        ifx client_index != -1 then *client_replay_protection[client_index] else null
    );

    if packet == null {
        return;
    }

    netcode_server_process_packet_internal(server, from, packet, sequence, encryption_index, client_index);
}

netcode_server_receive_packets :: (using server: *netcode_server_t) {
    assert(server != null);

    allowed_packets: AllowedPacketsBuf;
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = true;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = true;

    current_timestamp := current_time_monotonic();

    if config.network_simulator == null {
        // process packets received from socket

        while true {
            from: netcode_address_t;
            packet_data: [NETCODE_MAX_PACKET_BYTES] u8;
            packet_bytes := 0;

            if config.override_send_and_receive {
                assert(config.receive_packet_override != null);
                packet_bytes = config.receive_packet_override(config.callback_context, *from, packet_data);
            } else {
                if socket_holder.ipv4.handle != INVALID_SOCKET {
                    packet_bytes = netcode_socket_receive_packet(socket_holder.ipv4, *from, packet_data);
                }
                if packet_bytes == 0 && socket_holder.ipv6.handle != INVALID_SOCKET {
                    packet_bytes = netcode_socket_receive_packet(socket_holder.ipv6, *from, packet_data);
                }
            }

            if packet_bytes == 0 {
                break;
            }

            netcode_server_read_and_process_packet(server, from, .{ packet_bytes, packet_data.data }, current_timestamp, allowed_packets);
        }
    } else {
        // process packets received from network simulator

        num_packets_received := netcode_network_simulator_receive_packets(
            config.network_simulator,
            address,
            NETCODE_SERVER_MAX_RECEIVE_PACKETS,
            receive_packet_data,
            receive_from
        );

        for 0..num_packets_received-1 {
            netcode_server_read_and_process_packet(server, receive_from[it], receive_packet_data[it], current_timestamp, allowed_packets);
            array_reset(*receive_packet_data[it]);
        }
    }
}

netcode_server_send_packets :: (using server: *netcode_server_t) {
    assert(server != null);

    if !running {
        return;
    }

    for 0..max_clients-1 {
        if client_connected[it] && !client_loopback[it] && (time >= client_last_packet_send_time[it] + milliseconds_to_apollo(1000 / NETCODE_PACKET_SEND_RATE)) {
            netcode_log(.VERY_VERBOSE_ONLY, "server sent connection keep alive packet to client %\n", it);
            packet: netcode_connection_keep_alive_packet_t;
            assert(packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
            packet.client_index = it;
            packet.max_clients = max_clients;
            netcode_server_send_client_packet(server, *packet, it);
        }
    }
}

netcode_server_check_for_timeouts :: (using server: *netcode_server_t) {
    assert(server != null);

    if !running {
        return;
    }

    for 0..max_clients-1 {
        if client_connected[it] && client_timeout[it] > .{} && !client_loopback[it] && (client_last_packet_receive_time[it] + client_timeout[it] <= time) {
            netcode_log(.VERBOSE_ONLY, "server timed out client %\n", it);
            netcode_server_disconnect_client_internal(server, it, false);
        }
    }
}
