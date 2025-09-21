netcode_test :: () {
    log("\n--- Netcode --------------------------------------------------------------------\n");
    log("Running tests...\n");
    netcode_init();
    TEST(test_queue);
    TEST(test_sequence);
    TEST(test_address);
    TEST(test_connect_token);
    TEST(test_challenge_token);
    TEST(test_connection_request_packet);
    TEST(test_connection_denied_packet);
    TEST(test_connection_challenge_packet);
    TEST(test_connection_response_packet);
    TEST(test_connection_keep_alive_packet);
    TEST(test_connection_payload_packet);
    TEST(test_connection_disconnect_packet);
    TEST(test_connect_token_public);
    TEST(test_encryption_manager);
    TEST(test_replay_protection);
    TEST(test_client_create);
    TEST(test_server_create);
    TEST(test_client_server_connect);
    TEST(test_client_server_ipv4_socket_connect);
    TEST(test_client_server_ipv6_socket_connect);
    TEST(test_client_server_keep_alive);
    TEST(test_client_server_multiple_clients);
    TEST(test_client_server_multiple_servers);
    TEST(test_client_error_connect_token_expired);
    TEST(test_client_error_invalid_connect_token);
    TEST(test_client_error_connection_timed_out);
    TEST(test_client_error_connection_response_timeout);
    TEST(test_client_error_connection_request_timeout);
    TEST(test_client_error_connection_denied);
    TEST(test_client_side_disconnect);
    TEST(test_server_side_disconnect);
    TEST(test_client_reconnect);
    TEST(test_disable_timeout);
    TEST(test_loopback);
    TEST(test_address_map);
    netcode_term();
    log("Passed!\n");
    reset_temporary_storage();
}

#scope_file

#import "Random";
#import "Assertive";

TEST :: (test: (), $call := #caller_code) {
    assert_test(test, ENABLE_LOGGING, call);
}

// NOTE(dlb): Timestamps get truncated to the nearest millisecond when being sent over the wire
current_time_ms :: () -> Apollo_Time {
    return milliseconds_to_apollo(to_milliseconds(current_time_monotonic()));
}

test_queue :: () {
    queue: netcode_packet_queue_t;

    assert_equal(queue.num_packets, 0);
    assert_equal(queue.start_index, 0);

    // attempting to pop a packet off an empty queue should return null

    assert_null(netcode_packet_queue_pop(*queue));

    // add some packets to the queue and make sure they pop off in the correct order
    {
        NUM_PACKETS :: 100;

        packets: [NUM_PACKETS] *netcode_connection_packet_t;

        for 0..NUM_PACKETS-1 {
            // NOTE(dlb): Huh? Why the weird malloc sizes?
            packets[it] = New(netcode_connection_packet_t);
            assert_true(netcode_packet_queue_push(*queue, packets[it], cast(u64) it));
        }

        assert_equal(queue.num_packets, NUM_PACKETS);

        for 0..NUM_PACKETS-1 {
            packet, sequence := netcode_packet_queue_pop(*queue);
            assert_equal(sequence, cast(u64) it);
            assert_equal(packet, packets[it]);
            free(packet);
        }
    }

    // after all entries are popped off, the queue is empty, so calls to pop should return null

    assert_equal(queue.num_packets, 0);

    assert_null(netcode_packet_queue_pop(*queue));

    // test that the packet queue can be filled to max capacity

    packets: [NETCODE_PACKET_QUEUE_SIZE] *netcode_connection_packet_t;

    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        packets[it] = New(netcode_connection_packet_t);
        assert_true(netcode_packet_queue_push(*queue, packets[it], cast(u64) it));
    }

    assert_equal(queue.num_packets, NETCODE_PACKET_QUEUE_SIZE);

    // when the queue is full, attempting to push a packet should fail and return 0

    another_packet := New(netcode_connection_packet_t);
    assert_false(netcode_packet_queue_push(*queue, another_packet, 0));

    // make sure all packets pop off in the correct order

    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        packet, sequence := netcode_packet_queue_pop(*queue);
        assert_equal(sequence, cast(u64) it);
        assert_equal(packet, packets[it]);
        free(packet);
    }

    // add some packets again

    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        packets[it] = New(netcode_connection_packet_t);
        assert_true(netcode_packet_queue_push(*queue, packets[it], cast(u64) it));
    }

    // clear the queue and make sure that all packets are freed

    netcode_packet_queue_clear(*queue);

    assert_equal(queue.start_index, 0);
    assert_equal(queue.num_packets, 0);
    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        assert_null(queue.packet_data[it]);
    }
}

test_sequence :: () {
    assert_equal(netcode_sequence_number_bytes_required(0), 1);
    assert_equal(netcode_sequence_number_bytes_required(0x11), 1);
    assert_equal(netcode_sequence_number_bytes_required(0x1122), 2);
    assert_equal(netcode_sequence_number_bytes_required(0x112233), 3);
    assert_equal(netcode_sequence_number_bytes_required(0x11223344), 4);
    assert_equal(netcode_sequence_number_bytes_required(0x1122334455), 5);
    assert_equal(netcode_sequence_number_bytes_required(0x112233445566), 6);
    assert_equal(netcode_sequence_number_bytes_required(0x11223344556677), 7);
    assert_equal(netcode_sequence_number_bytes_required(0x1122334455667788), 8);
}

test_address :: () {
    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("[", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("[]", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("[]:", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address(":", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("1", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("12", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("123", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("1234", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("1234.0.12313.0000", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("1234.0.12313.0000.0.0.0.0.0", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address(".", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("..", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("...", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address("....", *address), NETCODE_ERROR);
        assert_equal(netcode_parse_address(".....", *address), NETCODE_ERROR);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("107.77.207.77", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV4);
        assert_equal(address.port, 0);
        assert_equal(address.data.ipv4[0], 107);
        assert_equal(address.data.ipv4[1], 77);
        assert_equal(address.data.ipv4[2], 207);
        assert_equal(address.data.ipv4[3], 77);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("127.0.0.1", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV4);
        assert_equal(address.port, 0);
        assert_equal(address.data.ipv4[0], 127);
        assert_equal(address.data.ipv4[1], 0);
        assert_equal(address.data.ipv4[2], 0);
        assert_equal(address.data.ipv4[3], 1);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("107.77.207.77:40000", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV4);
        assert_equal(address.port, 40000);
        assert_equal(address.data.ipv4[0], 107);
        assert_equal(address.data.ipv4[1], 77);
        assert_equal(address.data.ipv4[2], 207);
        assert_equal(address.data.ipv4[3], 77);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("127.0.0.1:40000", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV4);
        assert_equal(address.port, 40000);
        assert_equal(address.data.ipv4[0], 127);
        assert_equal(address.data.ipv4[1], 0);
        assert_equal(address.data.ipv4[2], 0);
        assert_equal(address.data.ipv4[3], 1);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("fe80::202:b3ff:fe1e:8329", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV6);
        assert_equal(address.port, 0);
        assert_equal(address.data.ipv6[0], 0xfe80);
        assert_equal(address.data.ipv6[1], 0x0000);
        assert_equal(address.data.ipv6[2], 0x0000);
        assert_equal(address.data.ipv6[3], 0x0000);
        assert_equal(address.data.ipv6[4], 0x0202);
        assert_equal(address.data.ipv6[5], 0xb3ff);
        assert_equal(address.data.ipv6[6], 0xfe1e);
        assert_equal(address.data.ipv6[7], 0x8329);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("::", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV6);
        assert_equal(address.port, 0);
        assert_equal(address.data.ipv6[0], 0x0000);
        assert_equal(address.data.ipv6[1], 0x0000);
        assert_equal(address.data.ipv6[2], 0x0000);
        assert_equal(address.data.ipv6[3], 0x0000);
        assert_equal(address.data.ipv6[4], 0x0000);
        assert_equal(address.data.ipv6[5], 0x0000);
        assert_equal(address.data.ipv6[6], 0x0000);
        assert_equal(address.data.ipv6[7], 0x0000);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("::1", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV6);
        assert_equal(address.port, 0);
        assert_equal(address.data.ipv6[0], 0x0000);
        assert_equal(address.data.ipv6[1], 0x0000);
        assert_equal(address.data.ipv6[2], 0x0000);
        assert_equal(address.data.ipv6[3], 0x0000);
        assert_equal(address.data.ipv6[4], 0x0000);
        assert_equal(address.data.ipv6[5], 0x0000);
        assert_equal(address.data.ipv6[6], 0x0000);
        assert_equal(address.data.ipv6[7], 0x0001);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("[fe80::202:b3ff:fe1e:8329]:40000", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV6);
        assert_equal(address.port, 40000);
        assert_equal(address.data.ipv6[0], 0xfe80);
        assert_equal(address.data.ipv6[1], 0x0000);
        assert_equal(address.data.ipv6[2], 0x0000);
        assert_equal(address.data.ipv6[3], 0x0000);
        assert_equal(address.data.ipv6[4], 0x0202);
        assert_equal(address.data.ipv6[5], 0xb3ff);
        assert_equal(address.data.ipv6[6], 0xfe1e);
        assert_equal(address.data.ipv6[7], 0x8329);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("[::]:40000", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV6);
        assert_equal(address.port, 40000);
        assert_equal(address.data.ipv6[0], 0x0000);
        assert_equal(address.data.ipv6[1], 0x0000);
        assert_equal(address.data.ipv6[2], 0x0000);
        assert_equal(address.data.ipv6[3], 0x0000);
        assert_equal(address.data.ipv6[4], 0x0000);
        assert_equal(address.data.ipv6[5], 0x0000);
        assert_equal(address.data.ipv6[6], 0x0000);
        assert_equal(address.data.ipv6[7], 0x0000);
    }

    {
        address: netcode_address_t;
        assert_equal(netcode_parse_address("[::1]:40000", *address), NETCODE_OK);
        assert_equal(address.type, NETCODE_ADDRESS_IPV6);
        assert_equal(address.port, 40000);
        assert_equal(address.data.ipv6[0], 0x0000);
        assert_equal(address.data.ipv6[1], 0x0000);
        assert_equal(address.data.ipv6[2], 0x0000);
        assert_equal(address.data.ipv6[3], 0x0000);
        assert_equal(address.data.ipv6[4], 0x0000);
        assert_equal(address.data.ipv6[5], 0x0000);
        assert_equal(address.data.ipv6[6], 0x0000);
        assert_equal(address.data.ipv6[7], 0x0001);
    }
}

TEST_PROTOCOL_ID          : u64 : 0x1122334455667788;
TEST_CLIENT_ID            : u64 : 0x1;
TEST_SERVER_PORT          :: 40000;
TEST_CONNECT_TOKEN_EXPIRY :: #run seconds_to_apollo(30);
TEST_TIMEOUT_SECONDS      :: #run seconds_to_apollo(15);

test_connect_token :: () {
    // generate a connect token

    server_address: netcode_address_t;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    input_token: netcode_connect_token_private_t;

    netcode_generate_connect_token_private(*input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, .[ server_address ], user_data);

    assert_equal(input_token.client_id, TEST_CLIENT_ID);
    assert_equal(input_token.num_server_addresses, 1);
    assert_true(array_equal(input_token.user_data, user_data));
    assert_true(netcode_address_equal(input_token.server_addresses[0], server_address));

    // write it to a buffer

    buffer: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(*input_token, buffer);

    // encrypt the buffer

    expire_timestamp := current_time_monotonic() + seconds_to_apollo(30);
    nonce: BigNonceBuf;
    netcode_generate_nonce(nonce);
    key: EncryptionKeyBuf;
    netcode_generate_key(key);

    assert_equal(netcode_encrypt_connect_token_private(buffer, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, nonce, key), NETCODE_OK);

    // decrypt the buffer

    assert_equal(netcode_decrypt_connect_token_private(buffer, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, nonce, key), NETCODE_OK);

    // read the connect token back in

    output_token: netcode_connect_token_private_t;

    assert_equal(netcode_read_connect_token_private(buffer, *output_token), NETCODE_OK);

    // make sure that everything matches the original connect token

    assert_equal(output_token.client_id, input_token.client_id);
    assert_equal(output_token.timeout_seconds, input_token.timeout_seconds);
    assert_equal(output_token.num_server_addresses, input_token.num_server_addresses);
    assert_true(netcode_address_equal(output_token.server_addresses[0], input_token.server_addresses[0]));
    assert_true(array_equal(output_token.client_to_server_key, input_token.client_to_server_key));
    assert_true(array_equal(output_token.server_to_client_key, input_token.server_to_client_key));
    assert_true(array_equal(output_token.user_data, input_token.user_data));
}

test_challenge_token :: () {
    // generate a challenge token

    input_token: netcode_challenge_token_t;

    input_token.client_id = TEST_CLIENT_ID;
    netcode_random_bytes(input_token.user_data);

    // write it to a buffer

    buffer: ChallengeTokenBuf;

    netcode_write_challenge_token(*input_token, buffer);

    // encrypt the buffer

    sequence: u64 = 1000;
    key: EncryptionKeyBuf;
    netcode_generate_key(key);

    assert_equal(netcode_encrypt_challenge_token(buffer, sequence, key), NETCODE_OK);

    // decrypt the buffer

    assert_equal(netcode_decrypt_challenge_token(buffer, sequence, key), NETCODE_OK);

    // read the challenge token back in

    output_token: netcode_challenge_token_t;

    assert_equal(netcode_read_challenge_token(buffer, *output_token), NETCODE_OK);

    // make sure that everything matches the original challenge token

    assert_equal(output_token.client_id, input_token.client_id);
    assert_true(array_equal(output_token.user_data, input_token.user_data));
}

test_connection_request_packet :: () {
    // generate a connect token

    server_address: netcode_address_t;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    input_token: netcode_connect_token_private_t;

    netcode_generate_connect_token_private(*input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, .[ server_address ], user_data);

    assert_equal(input_token.client_id, TEST_CLIENT_ID);
    assert_equal(input_token.num_server_addresses, 1);
    assert_true(array_equal(input_token.user_data, user_data));
    assert_true(netcode_address_equal(input_token.server_addresses[0], server_address));

    // write the conect token to a buffer (non-encrypted)

    connect_token_data: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(*input_token, connect_token_data);

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    encrypted_connect_token_data: ConnectTokenPrivateDataBuf;
    array_copy_data(encrypted_connect_token_data, connect_token_data);

    connect_token_expire_timestamp := current_time_ms() + seconds_to_apollo(30);
    connect_token_nonce: BigNonceBuf;
    netcode_generate_nonce(connect_token_nonce);
    connect_token_key: EncryptionKeyBuf;
    netcode_generate_key(connect_token_key);

    assert_equal(netcode_encrypt_connect_token_private(encrypted_connect_token_data, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID,
        connect_token_expire_timestamp, connect_token_nonce, connect_token_key), NETCODE_OK);

    // setup a connection request packet wrapping the encrypted connect token

    input_packet: netcode_connection_request_packet_t;
    assert_equal(input_packet.type, NETCODE_CONNECTION_REQUEST_PACKET);

    array_copy_data(input_packet.version_info, NETCODE_VERSION_INFO);
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    array_copy_data(input_packet.connect_token_nonce, connect_token_nonce);
    array_copy_data(input_packet.connect_token_data, encrypted_connect_token_data);

    // write the connection request packet to a buffer

    buffer: [2048] u8;
    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);
    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), *connect_token_key, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_REQUEST_PACKET);
    p := cast(*netcode_connection_request_packet_t) output_packet;
    assert_true(array_equal(p.version_info, input_packet.version_info));
    assert_equal(p.protocol_id, input_packet.protocol_id);
    assert_equal(p.connect_token_expire_timestamp, input_packet.connect_token_expire_timestamp);
    assert_true(array_equal(p.connect_token_nonce, input_packet.connect_token_nonce));
    assert_equal(memcmp(p.connect_token_data.data, connect_token_data.data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES), 0);

    free(output_packet);
}

test_connection_denied_packet :: () {
    // setup a connection denied packet

    input_packet: netcode_connection_denied_packet_t;
    assert_equal(input_packet.type, NETCODE_CONNECTION_DENIED_PACKET);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;

    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_DENIED_PACKET);

    free(output_packet);
}

test_connection_challenge_packet :: () {
    // setup a connection challenge packet

    input_packet: netcode_connection_challenge_packet_t;
    assert_equal(input_packet.type, NETCODE_CONNECTION_CHALLENGE_PACKET);
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes(input_packet.challenge_token_data);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;

    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_CHALLENGE_PACKET);
    p := cast(*netcode_connection_challenge_packet_t) output_packet;
    assert_equal(p.challenge_token_sequence, input_packet.challenge_token_sequence);
    assert_true(array_equal(p.challenge_token_data, input_packet.challenge_token_data));

    free(output_packet);
}

test_connection_response_packet :: () {
    // setup a connection response packet

    input_packet: netcode_connection_response_packet_t;
    assert_equal(input_packet.type, NETCODE_CONNECTION_RESPONSE_PACKET);
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes(input_packet.challenge_token_data);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence :=  netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_RESPONSE_PACKET);
    p := cast(*netcode_connection_response_packet_t) output_packet;
    assert_equal(p.challenge_token_sequence, input_packet.challenge_token_sequence);
    assert_true(array_equal(p.challenge_token_data, input_packet.challenge_token_data));

    free(output_packet);
}

test_connection_keep_alive_packet :: () {
    // setup a connection keep alive packet

    input_packet: netcode_connection_keep_alive_packet_t;
    assert_equal(input_packet.type, NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence :=  netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
    p := cast(*netcode_connection_keep_alive_packet_t) output_packet;
    assert_equal(p.client_index, input_packet.client_index);
    assert_equal(p.max_clients, input_packet.max_clients);

    free(output_packet);
}

test_connection_payload_packet :: () {
    // setup a connection payload packet

    input_packet := netcode_create_payload_packet(NETCODE_MAX_PAYLOAD_BYTES);

    assert_equal(input_packet.type, NETCODE_CONNECTION_PAYLOAD_PACKET);
    assert_equal(input_packet.payload_data.count, NETCODE_MAX_PAYLOAD_BYTES);

    netcode_random_bytes(input_packet.payload_data);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence :=  netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_PAYLOAD_PACKET);
    p := cast(*netcode_connection_payload_packet_t) output_packet;
    assert_equal(p.payload_data.count, input_packet.payload_data.count);
    assert_equal(memcmp(p.payload_data.data, input_packet.payload_data.data, input_packet.payload_data.count), 0);

    free(input_packet);
    free(output_packet);
}

test_connection_disconnect_packet :: () {
    // setup a connection disconnect packet

    input_packet: netcode_connection_disconnect_packet_t;
    assert_equal(input_packet.type, NETCODE_CONNECTION_DISCONNECT_PACKET);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    assert_true(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    assert_not_null(output_packet);

    // make sure the read packet matches what was written

    assert_equal(output_packet.type, NETCODE_CONNECTION_DISCONNECT_PACKET);

    free(output_packet);
}

test_connect_token_public :: () {
    // generate a private connect token

    server_address: netcode_address_t;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    connect_token_private: netcode_connect_token_private_t;
    netcode_generate_connect_token_private(*connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, .[ server_address ], user_data);

    assert_equal(connect_token_private.client_id, TEST_CLIENT_ID);
    assert_equal(connect_token_private.num_server_addresses, 1);
    assert_true(array_equal(connect_token_private.user_data, user_data));
    assert_true(netcode_address_equal(connect_token_private.server_addresses[0], server_address));

    // write it to a buffer

    connect_token_private_data: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(*connect_token_private, connect_token_private_data);

    // encrypt the buffer

    // NOTE(dlb): Timestamps get truncated to the nearest millisecond when being sent over the wire
    create_timestamp := current_time_ms();
    expire_timestamp := create_timestamp + seconds_to_apollo(30);
    connect_token_nonce: BigNonceBuf;
    netcode_generate_nonce(connect_token_nonce);
    key: EncryptionKeyBuf;
    netcode_generate_key(key);
    assert_equal(netcode_encrypt_connect_token_private(connect_token_private_data, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID,
        expire_timestamp, connect_token_nonce, key), NETCODE_OK);

    // wrap a public connect token around the private connect token data

    input_connect_token: netcode_connect_token_t;
    array_copy_data(input_connect_token.version_info, NETCODE_VERSION_INFO);
    input_connect_token.protocol_id = TEST_PROTOCOL_ID;
    input_connect_token.create_timestamp = create_timestamp;
    input_connect_token.expire_timestamp = expire_timestamp;
    array_copy_data(input_connect_token.nonce, connect_token_nonce);
    array_copy_data(input_connect_token.private_data, connect_token_private_data);
    input_connect_token.num_server_addresses = 1;
    input_connect_token.server_addresses[0] = server_address;
    array_copy_data(input_connect_token.client_to_server_key, connect_token_private.client_to_server_key);
    array_copy_data(input_connect_token.server_to_client_key, connect_token_private.server_to_client_key);
    input_connect_token.timeout_seconds = TEST_TIMEOUT_SECONDS;

    // write the connect token to a buffer

    buffer: ConnectTokenBuf;
    netcode_write_connect_token(*input_connect_token, buffer);

    // read the buffer back in

    output_connect_token: netcode_connect_token_t;
    assert_equal(netcode_read_connect_token(buffer, *output_connect_token), NETCODE_OK);

    // make sure the public connect token matches what was written

    assert_true(array_equal(output_connect_token.version_info, input_connect_token.version_info));
    assert_equal(output_connect_token.protocol_id, input_connect_token.protocol_id);
    assert_equal(output_connect_token.create_timestamp, input_connect_token.create_timestamp);
    assert_equal(output_connect_token.expire_timestamp, input_connect_token.expire_timestamp);
    assert_true(array_equal(output_connect_token.nonce, input_connect_token.nonce));
    assert_true(array_equal(output_connect_token.private_data, input_connect_token.private_data));
    assert_equal(output_connect_token.num_server_addresses, input_connect_token.num_server_addresses);
    assert_true(netcode_address_equal(output_connect_token.server_addresses[0], input_connect_token.server_addresses[0]));
    assert_true(array_equal(output_connect_token.client_to_server_key, input_connect_token.client_to_server_key));
    assert_true(array_equal(output_connect_token.server_to_client_key, input_connect_token.server_to_client_key));
    assert_equal(output_connect_token.timeout_seconds, input_connect_token.timeout_seconds);
}

test_encryption_manager :: () {
    encryption_manager: netcode_encryption_manager_t;

    netcode_encryption_manager_reset(*encryption_manager);

    time := seconds_to_apollo(100);

    // generate some test encryption mappings

    encryption_mapping_t :: struct {
        address     : netcode_address_t;
        send_key    : EncryptionKeyBuf;
        receive_key : EncryptionKeyBuf;
    }

    NUM_ENCRYPTION_MAPPINGS :: 5;

    encryption_mapping: [NUM_ENCRYPTION_MAPPINGS] encryption_mapping_t;

    for * encryption_mapping {
        it.address.type = NETCODE_ADDRESS_IPV6;
        it.address.data.ipv6[7] = 1;
        it.address.port = cast(u16) (20000 + it_index);
        netcode_generate_key(it.send_key);
        netcode_generate_key(it.receive_key);
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        assert_equal(encryption_index, -1);

        assert_null(netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index));
        assert_null(netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index));

        assert_true(netcode_encryption_manager_add_encryption_mapping(*encryption_manager, it.address, it.send_key, it.receive_key, time, seconds_to_apollo(-1), TEST_TIMEOUT_SECONDS));

        encryption_index = netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        assert_not_null(send_key);
        assert_not_null(receive_key);

        assert_true(array_equal(send_key.*, it.send_key));
        assert_true(array_equal(receive_key.*, it.receive_key));
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        address: netcode_address_t;
        address.type = NETCODE_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        assert_false(netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, address, time));
    }

    // remove the first and last encryption mappings

    assert_true(netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time));

    assert_true(netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, time));

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        if it_index > 0 && it_index < NUM_ENCRYPTION_MAPPINGS - 1 {
            assert_not_null(send_key);
            assert_not_null(receive_key);

            assert_true(array_equal(send_key.*, it.send_key));
            assert_true(array_equal(receive_key.*, it.receive_key));
        } else {
            assert_null(send_key);
            assert_null(receive_key);
        }
    }

    // add the encryption mappings back in

    assert_true(netcode_encryption_manager_add_encryption_mapping(
        *encryption_manager,
        encryption_mapping[0].address,
        encryption_mapping[0].send_key,
        encryption_mapping[0].receive_key,
        time,
        seconds_to_apollo(-1),
        TEST_TIMEOUT_SECONDS)
    );

    assert_true(netcode_encryption_manager_add_encryption_mapping(
        *encryption_manager,
        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address,
        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].send_key,
        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].receive_key,
        time,
        seconds_to_apollo(-1),
        TEST_TIMEOUT_SECONDS)
    );

    // all encryption mappings should be able to be looked up by address again

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        assert_not_null(send_key);
        assert_not_null(receive_key);

        assert_true(array_equal(send_key.*, it.send_key));
        assert_true(array_equal(receive_key.*, it.receive_key));
    }

    // check that encryption mappings time out properly

    time += TEST_TIMEOUT_SECONDS * 2;

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        assert_null(send_key);
        assert_null(receive_key);
    }

    // add the same encryption mappings after timeout

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        assert_equal(encryption_index, -1);

        assert_null(netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index));
        assert_null(netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index));

        assert_true(netcode_encryption_manager_add_encryption_mapping(
            *encryption_manager,
            it.address,
            it.send_key,
            it.receive_key,
            time,
            seconds_to_apollo(-1),
            TEST_TIMEOUT_SECONDS)
        );

        encryption_index = netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        assert_not_null(send_key);
        assert_not_null(receive_key);

        assert_true(array_equal(send_key.*, it.send_key));
        assert_true(array_equal(receive_key.*, it.receive_key));
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    netcode_encryption_manager_reset(*encryption_manager);

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        assert_null(send_key);
        assert_null(receive_key);
    }

    // test the expire time for encryption mapping works as expected

    assert_true(netcode_encryption_manager_add_encryption_mapping(
        *encryption_manager,
        encryption_mapping[0].address,
        encryption_mapping[0].send_key,
        encryption_mapping[0].receive_key,
        time,
        time + seconds_to_apollo(1),
        TEST_TIMEOUT_SECONDS)
    );

    encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time);

    assert_not_equal(encryption_index, -1);

    assert_equal(netcode_encryption_manager_find_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time + milliseconds_to_apollo(1100)), -1);

    netcode_encryption_manager_set_expire_time(*encryption_manager, encryption_index, seconds_to_apollo(-1));

    assert_equal(netcode_encryption_manager_find_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time), encryption_index);
}

test_replay_protection :: () {
    replay_protection: netcode_replay_protection_t;

    for 0..1 {
        netcode_replay_protection_reset(*replay_protection);

        assert_equal(replay_protection.most_recent_sequence, cast(u64) 0);

        // the first time we receive packets, they should not be already received

        MAX_SEQUENCE :: NETCODE_REPLAY_PROTECTION_BUFFER_SIZE * 4;

        for 0..MAX_SEQUENCE-1 {
            sequence := cast(u64) it;
            assert_false(netcode_replay_protection_already_received(*replay_protection, sequence));
            netcode_replay_protection_advance_sequence(*replay_protection, sequence);
        }

        // old packets outside buffer should be considered already received

        assert_true(netcode_replay_protection_already_received(*replay_protection, 0));

        // packets received a second time should be flagged already received

        for MAX_SEQUENCE-10..MAX_SEQUENCE-1 {
            sequence := cast(u64) it;
            assert_true(netcode_replay_protection_already_received(*replay_protection, sequence));
        }

        // jumping ahead to a much higher sequence should be considered not already received

        assert_false(netcode_replay_protection_already_received(*replay_protection, MAX_SEQUENCE + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE));

        // old packets should be considered already received

        for 0..MAX_SEQUENCE-1 {
            sequence := cast(u64) it;
            assert_true(netcode_replay_protection_already_received(*replay_protection, sequence));
        }
    }
}

test_client_create :: () {
    {
        client_config: netcode_client_config_t;
        client := netcode_client_create("127.0.0.1:40000", *client_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("127.0.0.1:40000", *test_address);

        assert_not_null(client);
        assert_not_equal(client.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_equal(client.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(client.address, *test_address));

        netcode_client_destroy(client);
    }

    {
        client_config: netcode_client_config_t;
        client := netcode_client_create("[::]:50000", *client_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("[::]:50000", *test_address);

        assert_not_null(client);
        assert_equal(client.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_not_equal(client.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(client.address, *test_address));

        netcode_client_destroy(client);
    }

    {
        client_config: netcode_client_config_t;
        client := netcode_client_create_overload("127.0.0.1:40000", "[::]:50000", *client_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("127.0.0.1:40000", *test_address);

        assert_not_null(client);
        assert_not_equal(client.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_not_equal(client.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(client.address, *test_address));

        netcode_client_destroy(client);
    }

    {
        client_config: netcode_client_config_t;
        client := netcode_client_create_overload("[::]:50000", "127.0.0.1:40000", *client_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("[::]:50000", *test_address);

        assert_not_null(client);
        assert_not_equal(client.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_not_equal(client.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(client.address, *test_address));

        netcode_client_destroy(client);
    }
}

test_server_create :: () {
    {
        server_config: netcode_server_config_t;
        server := netcode_server_create("127.0.0.1:40000", *server_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("127.0.0.1:40000", *test_address);

        assert_not_null(server);
        assert_not_equal(server.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_equal(server.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(*server.address, *test_address));

        netcode_server_destroy(server);
    }

    {
        server_config: netcode_server_config_t;
        server := netcode_server_create("[::1]:50000", *server_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("[::1]:50000", *test_address);

        assert_not_null(server);
        assert_equal(server.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_not_equal(server.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(*server.address, *test_address));

        netcode_server_destroy(server);
    }

    {
        server_config: netcode_server_config_t;
        server := netcode_server_create_overload("127.0.0.1:40000", "[::1]:50000", *server_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("127.0.0.1:40000", *test_address);

        assert_not_null(server);
        assert_not_equal(server.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_not_equal(server.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(*server.address, *test_address));

        netcode_server_destroy(server);
    }

    {
        server_config: netcode_server_config_t;
        server := netcode_server_create_overload("[::1]:50000", "127.0.0.1:40000", *server_config, .{});

        test_address: netcode_address_t;
        netcode_parse_address("[::1]:50000", *test_address);

        assert_not_null(server);
        assert_not_equal(server.socket_holder.ipv4.handle, INVALID_SOCKET);
        assert_not_equal(server.socket_holder.ipv6.handle, INVALID_SOCKET);
        assert_true(netcode_address_equal(*server.address, *test_address));

        netcode_server_destroy(server);
    }
}

private_key: EncryptionKeyBuf : .[
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
    0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
    0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1
];

test_client_server_connect :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;

    client := netcode_client_create("[::]:50000", *client_config, time);

    assert_not_null(client);

    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server_address := "[::1]:40000";
    server := netcode_server_create(server_address, *server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    connect_token: ConnectTokenBuf;
    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);
    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    server_num_packets_received := 0;
    client_num_packets_received := 0;

    packet_data: [NETCODE_MAX_PACKET_SIZE] u8;
    for * packet_data {
        it.* = cast(u8) (it_index & 0xFF);
    }

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        netcode_client_send_packet(client, packet_data);
        netcode_server_send_packet(server, 0, packet_data);

        while true {
            packet, packet_sequence := netcode_client_receive_packet(client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet.count), 0);
            client_num_packets_received += 1;
            netcode_client_free_packet(client, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 0);
            if (!packet)
                break;
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet.count), 0);
            server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        if client_num_packets_received >= 10 && server_num_packets_received >= 10 {
            if netcode_server_client_connected(server, 0) {
                netcode_server_disconnect_client(server, 0);
            }
        }

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_true(client_num_packets_received >= 10);
    assert_true(server_num_packets_received >= 10);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

client_server_socket_connect :: (client_address: string, client_address2: string, server_address: string, server_address2: string) {
    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client := netcode_client_create_overload(client_address, client_address2, client_config, time);
    assert_not_null(client);

    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    array_copy_data(server_config.private_key, private_key);
    server := netcode_server_create_overload(server_address, server_address2, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    connect_token: ConnectTokenBuf;
    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);
    netcode_client_connect(client, connect_token);

    while true {
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    netcode_server_destroy(server);
    netcode_client_destroy(client);
}

test_client_server_ipv4_socket_connect :: () {
    client_server_socket_connect("0.0.0.0:50000", .{}         , "127.0.0.1:40000", .{}          );
    client_server_socket_connect("0.0.0.0:50000", .{}         , "127.0.0.1:40000", "[::1]:40000");
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", .{}          );
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000");
}

test_client_server_ipv6_socket_connect :: () {
    client_server_socket_connect("[::]:50000"   , .{}         , "[::1]:40000", .{}              );
    client_server_socket_connect("[::]:50000"   , .{}         , "[::1]:40000", "127.0.0.1:40000");
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", .{}              );
    client_server_socket_connect("0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000");
}


test_client_server_keep_alive :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    // connect client to server

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;

    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server_address := "[::1]:40000";
    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    connect_token: ConnectTokenBuf;
    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);
    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // pump the client and server long enough that they would timeout without keep alive packets

    num_iterations := cast(int) (1.25 * to_seconds(TEST_TIMEOUT_SECONDS) / to_seconds(delta_time)) + 1;

    for 0..num_iterations-1 {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_server_multiple_clients :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    NUM_START_STOP_ITERATIONS :: 3;
    max_clients: [NUM_START_STOP_ITERATIONS] int = .[ 2, 32, 5 ];

    for 0..NUM_START_STOP_ITERATIONS-1 {
        // start the server with max # of clients for this iteration

        netcode_server_start(server, max_clients[it]);

        // create # of client objects for this iteration and connect to server

        clients := NewArray(max_clients[it], *netcode_client_t);
        assert_true(clients.count > 0);

        for * client: clients {
            client_address := tprint("[::]:%", 50000 + it_index);

            client.* = netcode_client_create(client_address, client_config, time);
            assert_not_null(client.*);

            client_id := random_get();
            connect_token: ConnectTokenBuf;
            user_data: UserDataBuf;
            netcode_random_bytes(user_data);

            assert_equal(netcode_generate_connect_token(
                .[ server_address ],
                .[ server_address ],
                TEST_CONNECT_TOKEN_EXPIRY,
                TEST_TIMEOUT_SECONDS,
                client_id,
                TEST_PROTOCOL_ID,
                private_key,
                user_data,
                connect_token
            ), NETCODE_OK);

            netcode_client_connect(client.*, connect_token);
        }

        // make sure all clients can connect

        while true {
            netcode_network_simulator_update(network_simulator, time);

            for client: clients {
                netcode_client_update(client, time);
            }

            netcode_server_update(server, time);

            num_connected_clients := 0;

            for client: clients {
                if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
                    break;
                }
                if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
                    num_connected_clients += 1;
                }
            }

            if num_connected_clients == clients.count {
                break;
            }

            time += delta_time;
        }

        assert_equal(netcode_server_num_connected_clients(server), clients.count);

        for client: clients {
            assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
            assert_true(netcode_server_client_connected(server, it_index));
        }

        // make sure all clients can exchange packets with the server

        server_num_packets_received := NewArray(clients.count, int);
        client_num_packets_received := NewArray(clients.count, int);

        packet_data: [NETCODE_MAX_PACKET_SIZE] u8;
        for * packet_data {
            it.* = cast(u8) (it_index & 0xFF);
        }

        while true {
            netcode_network_simulator_update(network_simulator, time);

            for client: clients {
                netcode_client_update(client, time);
            }

            netcode_server_update(server, time);

            for client: clients {
                netcode_client_send_packet(client, packet_data);
            }

            for clients {
                netcode_server_send_packet(server, it_index, packet_data);
            }

            for client: clients {
                while true {
                    packet, packet_sequence := netcode_client_receive_packet(client);
                    if packet.count == 0 {
                        break;
                    }
                    assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
                    assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
                    client_num_packets_received[it_index] += 1;
                    netcode_client_free_packet(client, packet);
                }
            }

            for clients {
                while true {
                    packet, packet_sequence := netcode_server_receive_packet(server, it_index);
                    if packet.count == 0 {
                        break;
                    }
                    assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
                    assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
                    server_num_packets_received[it_index] += 1;
                    netcode_server_free_packet(server, packet);
                }
            }

            num_clients_ready := 0;

            for clients {
                if client_num_packets_received[it_index] >= 1 && server_num_packets_received[it_index] >= 1 {
                    num_clients_ready += 1;
                }
            }

            if num_clients_ready == clients.count {
                break;
            }

            for client: clients {
                if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
                    assert(false, "a client disconnected, this test cannot complete");
                }
            }

            time += delta_time;
        }

        num_clients_ready := 0;

        for clients {
            if client_num_packets_received[it_index] >= 1 && server_num_packets_received[it_index] >= 1 {
                num_clients_ready += 1;
            }
        }

        assert_equal(num_clients_ready, clients.count);

        array_free(server_num_packets_received);
        array_free(client_num_packets_received);

        netcode_network_simulator_reset(network_simulator);

        for client: clients {
            netcode_client_destroy(client);
        }

        array_free(clients);

        netcode_server_stop(server);
    }

    netcode_server_destroy(server);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_server_multiple_servers :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);
    server := netcode_server_create("[::1]:40000", server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    // two offline servers, which will fail, and a third, which should succeed
    server_addresses := string.[ "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" ];
    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(server_addresses, server_addresses, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    server_num_packets_received := 0;
    client_num_packets_received := 0;

    packet_data: [NETCODE_MAX_PACKET_SIZE] u8;
    for * packet_data {
        it.* = cast(u8) (it_index & 0xFF);
    }

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        netcode_client_send_packet(client, packet_data);
        netcode_server_send_packet(server, 0, packet_data);

        while true {
            packet, packet_sequence := netcode_client_receive_packet(client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            client_num_packets_received += 1;
            netcode_client_free_packet(client, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 0);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        if client_num_packets_received >= 10 && server_num_packets_received >= 10 {
            if netcode_server_client_connected(server, 0) {
                netcode_server_disconnect_client(server, 0);
            }
        }

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_true(client_num_packets_received >= 10);
    assert_true(server_num_packets_received >= 10);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_error_connect_token_expired :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;
    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], .{}, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);
    netcode_client_update(client, time);
    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED);

    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_error_invalid_connect_token :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;

    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    connect_token: ConnectTokenBuf;
    netcode_random_bytes(connect_token);

    client_id := random_get();
    netcode_client_connect(client, connect_token);

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN);

    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_error_connection_timed_out :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    // connect a client to the server

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);
    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);
    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // now disable updating the server and verify that the client times out

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_error_connection_response_timeout :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);
    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    server.flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;
    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_error_connection_request_timeout :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(16);  // ~= 60 tps

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);
    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    server.flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;
    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_error_connection_denied :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    // start a server and connect one client

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);
    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // now attempt to connect a second client. the connection should be denied.

    client2 := netcode_client_create("[::]:50001", client_config, time);
    assert_not_null(client2);

    client_id2 := random_get();
    user_data2: UserDataBuf;
    netcode_random_bytes(user_data2);
    connect_token2: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id2, TEST_PROTOCOL_ID, private_key, user_data2, connect_token2), NETCODE_OK);

    netcode_client_connect(client2, connect_token2);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_client_update(client2, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client2) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_state(client2), NETCODE_CLIENT_STATE_CONNECTION_DENIED);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_client_destroy(client2);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_side_disconnect :: () {
    network_simulator := New(netcode_network_simulator_t);

    // start a server and connect one client

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

    netcode_client_disconnect(client);

    for 0..9 {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if !netcode_server_client_connected(server, 0) {
            break;
        }

        time += delta_time;
    }

    assert_false(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 0);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_server_side_disconnect :: () {
    network_simulator := New(netcode_network_simulator_t);

    // start a server and connect one client

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

    netcode_server_disconnect_client(server, 0);

    for 0..9 {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) == NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_DISCONNECTED);
    assert_false(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 0);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_client_reconnect :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    // start a server and connect one client

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server := netcode_server_create("[::1]:40000", server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // disconnect client on the server-side and wait until client sees the disconnect

    netcode_network_simulator_reset(network_simulator);
    netcode_server_disconnect_client(server, 0);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_DISCONNECTED);
    assert_false(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 0);

    // now reconnect the client and verify they connect

    netcode_network_simulator_reset(network_simulator);

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_disable_timeout :: () {
    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    client_config: netcode_client_config_t;
    client_config.network_simulator = network_simulator;
    client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(client);

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    array_copy_data(server_config.private_key, private_key);

    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    netcode_server_start(server, 1);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, seconds_to_apollo(-1), client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);
    netcode_client_connect(client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(client), 0);
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    server_num_packets_received := 0;
    client_num_packets_received := 0;

    packet_data: [NETCODE_MAX_PACKET_SIZE] u8;
    for * packet_data {
        it.* = cast(u8) (it_index & 0xFF);
    }

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        netcode_client_send_packet(client, packet_data);
        netcode_server_send_packet(server, 0, packet_data);

        while true {
            packet, packet_sequence := netcode_client_receive_packet(client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            client_num_packets_received += 1;
            netcode_client_free_packet(client, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 0);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        if client_num_packets_received >= 10 && server_num_packets_received >= 10 {
            if netcode_server_client_connected(server, 0) {
                netcode_server_disconnect_client(server, 0);
            }
        }

        if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += seconds_to_apollo(1000);  // normally this would timeout the client
    }

    assert_true(client_num_packets_received >= 10);
    assert_true(server_num_packets_received >= 10);

    netcode_server_destroy(server);
    netcode_client_destroy(client);
    netcode_network_simulator_destroy(network_simulator);
}

test_loopback_context_t :: struct {
    client: *netcode_client_t;
    server: *netcode_server_t;
    num_loopback_packets_sent_to_client: int;
    num_loopback_packets_sent_to_server: int;
};

client_send_loopback_packet_callback :: (ctx: *void, client_index: int, packet_data: [] u8, packet_sequence: u64) {
    assert_not_null(ctx);
    assert_equal(client_index, 0);
    assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
    for * packet_data {
        it.* = cast(u8) (it_index & 0xFF);
    }

    c := cast(*test_loopback_context_t) ctx;
    c.num_loopback_packets_sent_to_server += 1;
    netcode_server_process_loopback_packet(c.server, client_index, packet_data, packet_sequence);
}

server_send_loopback_packet_callback :: (ctx: *void, client_index: int, packet_data: [] u8, packet_sequence: u64) {
    assert_not_null(ctx);
    assert_equal(client_index, 0);
    assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
    for packet_data {
        assert_equal(it, cast(u8) (it_index & 0xFF));
    }

    c := cast(*test_loopback_context_t) ctx;
    c.num_loopback_packets_sent_to_client += 1;
    netcode_client_process_loopback_packet(c.client, packet_data, packet_sequence);
}

test_loopback :: () {
    ctx: test_loopback_context_t;

    network_simulator := New(netcode_network_simulator_t);

    network_simulator.latency_milliseconds = 250;
    network_simulator.jitter_milliseconds = 250;
    network_simulator.packet_loss_percent = 5;
    network_simulator.duplicate_packet_percent = 10;

    time: Apollo_Time;
    delta_time := milliseconds_to_apollo(100);

    // start the server

    server_address := "[::1]:40000";
    server_config: netcode_server_config_t;
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    server_config.callback_context = *ctx;
    server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;
    array_copy_data(server_config.private_key, private_key);

    server := netcode_server_create(server_address, server_config, time);
    assert_not_null(server);

    max_clients := 2;

    netcode_server_start(server, max_clients);

    ctx.server = server;

    // connect a loopback client in slot 0

    client_config: netcode_client_config_t;
    client_config.callback_context = *ctx;
    client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;
    client_config.network_simulator = network_simulator;

    loopback_client := netcode_client_create("[::]:50000", client_config, time);
    assert_not_null(loopback_client);
    netcode_client_connect_loopback(loopback_client, 0, max_clients);
    ctx.client = loopback_client;

    assert_equal(netcode_client_index(loopback_client), 0);
    assert_true(netcode_client_loopback(loopback_client));
    assert_equal(netcode_client_max_clients(loopback_client), max_clients);
    assert_equal(netcode_client_state(loopback_client), NETCODE_CLIENT_STATE_CONNECTED);

    loopback_client_id := random_get();
    loopback_user_data: UserDataBuf;
    netcode_server_connect_loopback_client(server, 0, loopback_client_id, loopback_user_data);

    assert_true(netcode_server_client_loopback(server, 0));
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    // connect a regular client in the other slot

    regular_client := netcode_client_create("[::]:50001", client_config, time);
    assert_not_null(regular_client);

    client_id := random_get();
    user_data: UserDataBuf;
    netcode_random_bytes(user_data);
    connect_token: ConnectTokenBuf;

    assert_equal(netcode_generate_connect_token(.[ server_address ], .[ server_address ], TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token), NETCODE_OK);

    netcode_client_connect(regular_client, connect_token);

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(regular_client, time);
        netcode_server_update(server, time);

        if netcode_client_state(regular_client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }
        if netcode_client_state(regular_client) == NETCODE_CLIENT_STATE_CONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_equal(netcode_client_state(regular_client), NETCODE_CLIENT_STATE_CONNECTED);
    assert_equal(netcode_client_index(regular_client), 1);
    assert_true(netcode_server_client_connected(server, 0));
    assert_true(netcode_server_client_connected(server, 1));
    assert_true(netcode_server_client_loopback(server, 0));
    assert_false(netcode_server_client_loopback(server, 1));
    assert_equal(netcode_server_num_connected_clients(server), 2);

    // test that we can exchange packets for the regular client and the loopback client

    loopback_client_num_packets_received := 0;
    loopback_server_num_packets_received := 0;
    regular_server_num_packets_received := 0;
    regular_client_num_packets_received := 0;

    packet_data: [NETCODE_MAX_PACKET_SIZE] u8;
    for * packet_data {
        it.* = cast(u8) (it_index & 0xFF);
    }

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(regular_client, time);
        netcode_server_update(server, time);

        netcode_client_send_packet(loopback_client, packet_data);
        netcode_client_send_packet(regular_client, packet_data);

        netcode_server_send_packet(server, 0, packet_data);
        netcode_server_send_packet(server, 1, packet_data);

        while true {
            packet, packet_sequence := netcode_client_receive_packet(loopback_client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            loopback_client_num_packets_received += 1;
            netcode_client_free_packet(loopback_client, packet);
        }

        while true {
            packet, packet_sequence := netcode_client_receive_packet(regular_client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            regular_client_num_packets_received += 1;
            netcode_client_free_packet(regular_client, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 0);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            loopback_server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 1);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            regular_server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        if loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
           regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10
        {
            break;
        }

        if netcode_client_state(regular_client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_true(loopback_client_num_packets_received >= 10);
    assert_true(loopback_server_num_packets_received >= 10);
    assert_true(regular_client_num_packets_received >= 10);
    assert_true(regular_server_num_packets_received >= 10);
    assert_true(ctx.num_loopback_packets_sent_to_client >= 10);
    assert_true(ctx.num_loopback_packets_sent_to_server >= 10);

    // verify that we can disconnect the loopback client

    assert_true(netcode_server_client_loopback(server, 0));
    assert_true(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 2);

    netcode_server_disconnect_loopback_client(server, 0);

    assert_false(netcode_server_client_loopback(server, 0));
    assert_false(netcode_server_client_connected(server, 0));
    assert_equal(netcode_server_num_connected_clients(server), 1);

    netcode_client_disconnect_loopback(loopback_client);

    assert_equal(netcode_client_state(loopback_client), NETCODE_CLIENT_STATE_DISCONNECTED);

    // verify that we can reconnect the loopback client

    loopback_client_id = random_get();
    netcode_server_connect_loopback_client(server, 0, loopback_client_id, loopback_user_data);

    assert_true(netcode_server_client_loopback(server, 0));
    assert_false(netcode_server_client_loopback(server, 1));
    assert_true(netcode_server_client_connected(server, 0));
    assert_true(netcode_server_client_connected(server, 1));
    assert_equal(netcode_server_num_connected_clients(server), 2);

    netcode_client_connect_loopback(loopback_client, 0, max_clients);

    assert_equal(netcode_client_index(loopback_client), 0);
    assert_true(netcode_client_loopback(loopback_client));
    assert_equal(netcode_client_max_clients(loopback_client), max_clients);
    assert_equal(netcode_client_state(loopback_client), NETCODE_CLIENT_STATE_CONNECTED);

    // verify that we can exchange packets for both regular and loopback client post reconnect

    loopback_server_num_packets_received = 0;
    loopback_client_num_packets_received = 0;
    regular_server_num_packets_received = 0;
    regular_client_num_packets_received = 0;
    ctx.num_loopback_packets_sent_to_client = 0;
    ctx.num_loopback_packets_sent_to_server = 0;

    while true {
        netcode_network_simulator_update(network_simulator, time);
        netcode_client_update(regular_client, time);
        netcode_server_update(server, time);

        netcode_client_send_packet(loopback_client, packet_data);
        netcode_client_send_packet(regular_client, packet_data);

        netcode_server_send_packet(server, 0, packet_data);
        netcode_server_send_packet(server, 1, packet_data);

        while true {
            packet, packet_sequence := netcode_client_receive_packet(loopback_client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            loopback_client_num_packets_received += 1;
            netcode_client_free_packet(loopback_client, packet);
        }

        while true {
            packet, packet_sequence := netcode_client_receive_packet(regular_client);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            regular_client_num_packets_received += 1;
            netcode_client_free_packet(regular_client, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 0);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            loopback_server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        while true {
            packet, packet_sequence := netcode_server_receive_packet(server, 1);
            if packet.count == 0 {
                break;
            }
            assert_equal(packet_data.count, NETCODE_MAX_PACKET_SIZE);
            assert_equal(memcmp(packet.data, packet_data.data, packet_data.count), 0);
            regular_server_num_packets_received += 1;
            netcode_server_free_packet(server, packet);
        }

        if loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
           regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10
        {
            break;
        }

        if netcode_client_state(regular_client) <= NETCODE_CLIENT_STATE_DISCONNECTED {
            break;
        }

        time += delta_time;
    }

    assert_true(loopback_client_num_packets_received >= 10);
    assert_true(loopback_server_num_packets_received >= 10);
    assert_true(regular_client_num_packets_received >= 10);
    assert_true(regular_server_num_packets_received >= 10);
    assert_true(ctx.num_loopback_packets_sent_to_server >= 10);
    assert_true(ctx.num_loopback_packets_sent_to_client >= 10);

    // verify the regular client times out but loopback client doesn't

    time += seconds_to_apollo(1000); // 100000.0;

    netcode_server_update(server, time);

    assert_true(netcode_server_client_connected(server, 0));
    assert_false(netcode_server_client_connected(server, 1));

    netcode_client_update(loopback_client, time);

    assert_equal(netcode_client_state(loopback_client), NETCODE_CLIENT_STATE_CONNECTED);

    // verify that disconnect all clients leaves loopback clients alone

    netcode_server_disconnect_all_clients(server);

    assert_true(netcode_server_client_connected(server, 0));
    assert_false(netcode_server_client_connected(server, 1));
    assert_true(netcode_server_client_loopback(server, 0));

    // clean up

    netcode_client_destroy(regular_client);
    netcode_client_destroy(loopback_client);
    netcode_server_destroy(server);
    netcode_network_simulator_destroy(network_simulator);
}

test_address_map :: () {
    str_address_1 := "107.77.207.77:40000";
    str_address_2 := "127.0.0.1:23650";
    str_address_3 := "fe80::202:b3ff:fe1e:8329";
    str_address_4 := "fe80::202:b3ff:fe1e:8330";

    map := netcode_address_map_create();

    address_set: netcode_address_t;
    address_get: netcode_address_t;
    address_delete: netcode_address_t;

    // Set ipv4
    netcode_parse_address(str_address_1, *address_set);
    assert_true(netcode_address_map_set(map, address_set, 0));

    // Set ipv6
    netcode_parse_address(str_address_3, *address_set);
    assert_true(netcode_address_map_set(map, address_set, 1));

    // Get ipv4
    netcode_parse_address(str_address_1, *address_get);
    assert_equal(netcode_address_map_get(map, address_get), 0);

    // Get ipv6
    netcode_parse_address(str_address_3, *address_get);
    assert_equal(netcode_address_map_get(map, address_get), 1);

    // Get non-existent ipv4
    netcode_parse_address(str_address_2, *address_get);
    assert_equal(netcode_address_map_get(map, address_get), -1);

    // Get non-existent ipv6
    netcode_parse_address(str_address_4, *address_get);
    assert_equal(netcode_address_map_get(map, address_get), -1);

    // Try to delete key, after that, the key should disappear
    netcode_parse_address(str_address_1, *address_delete);
    netcode_parse_address(str_address_1, *address_get);
    assert_true(netcode_address_map_delete(map, address_delete));
    assert_equal(netcode_address_map_get(map, address_get), -1);

    // Try to delete non-existent key
    netcode_parse_address(str_address_2, *address_delete);
    assert_false(netcode_address_map_delete(map, address_delete));

    netcode_address_map_destroy(map);
}