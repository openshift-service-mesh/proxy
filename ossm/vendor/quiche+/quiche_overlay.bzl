load("@rules_cc//cc:defs.bzl", "cc_library")

quiche_copts = [
    # hpack_huffman_decoder.cc overloads operator<<.
    "-Wno-unused-function",
    "-Wno-old-style-cast",
    # Envoy build should not fail if a dependency has a warning.
    "-Wno-error",
] + select({
    # Envoy platform headers include windows.h before winsock2.h.
    "@platforms//os:windows": [
        "-DWIN32_LEAN_AND_MEAN",
    ],
    "//conditions:default": [],
})

_EXTERNAL_DEPS = {
    "nghttp2": ["@nghttp2//:nghttp2"],
    "ssl": ["//:ssl_lib"],
}

# QUIC/HTTP3-specific library targets. Under --define=quiche_disable_http3=true
# (Envoy's --config=openssl) these are compiled as empty libraries: their srcs,
# hdrs and deps are dropped. This mirrors Envoy's WORKSPACE build, where the same
# targets are declared with envoy_quic_cc_library and their sources are excluded
# via envoy_select_enable_http3 when HTTP/3 is disabled. Without this, QUIC
# sources (e.g. quic_connection_id.cc, which references BoringSSL's SIPHASH_24)
# would be compiled against a non-BoringSSL SSL implementation and fail.
#
# Keep this in sync with the envoy_quic_cc_library / envoy_quic_cc_test_library
# targets in Envoy's bazel/external/quiche.BUILD.
_HTTP3_ONLY_LIBS = {
    "flow_label_lib": None,
    "quic_client_crypto_crypto_handshake_lib": None,
    "quic_client_crypto_tls_handshake_lib": None,
    "quic_client_session_lib": None,
    "quic_core_ack_timestamp_list_lib": None,
    "quic_core_alarm_factory_lib": None,
    "quic_core_alarm_lib": None,
    "quic_core_arena_scoped_ptr_lib": None,
    "quic_core_bandwidth_lib": None,
    "quic_core_blocked_writer_interface_lib": None,
    "quic_core_blocked_writer_list_lib": None,
    "quic_core_chaos_protector_lib": None,
    "quic_core_clock_lib": None,
    "quic_core_config_lib": None,
    "quic_core_congestion_control_bandwidth_sampler_lib": None,
    "quic_core_congestion_control_bbr2_lib": None,
    "quic_core_congestion_control_bbr3_sender_lib": None,
    "quic_core_congestion_control_bbr_lib": None,
    "quic_core_congestion_control_congestion_control_interface_lib": None,
    "quic_core_congestion_control_congestion_control_lib": None,
    "quic_core_congestion_control_general_loss_algorithm_lib": None,
    "quic_core_congestion_control_pacing_sender_lib": None,
    "quic_core_congestion_control_prague_sender_lib": None,
    "quic_core_congestion_control_rtt_stats_lib": None,
    "quic_core_congestion_control_tcp_cubic_bytes_lib": None,
    "quic_core_congestion_control_tcp_cubic_helper": None,
    "quic_core_congestion_control_uber_loss_algorithm_lib": None,
    "quic_core_congestion_control_windowed_filter_lib": None,
    "quic_core_connection_alarms_lib": None,
    "quic_core_connection_context_lib": None,
    "quic_core_connection_id_generator_interface_lib": None,
    "quic_core_connection_id_manager": None,
    "quic_core_connection_lib": None,
    "quic_core_connection_stats_lib": None,
    "quic_core_constants_lib": None,
    "quic_core_crypto_boring_utils_lib": None,
    "quic_core_crypto_certificate_view_lib": None,
    "quic_core_crypto_client_proof_source_lib": None,
    "quic_core_crypto_crypto_handshake_lib": None,
    "quic_core_crypto_encryption_lib": None,
    "quic_core_crypto_hkdf_lib": None,
    "quic_core_crypto_proof_source_lib": None,
    "quic_core_crypto_proof_source_x509_lib": None,
    "quic_core_crypto_tls_handshake_lib": None,
    "quic_core_data_lib": None,
    "quic_core_deterministic_connection_id_generator_lib": None,
    "quic_core_framer_lib": None,
    "quic_core_frames_frames_lib": None,
    "quic_core_http_client_lib": None,
    "quic_core_http_header_list_lib": None,
    "quic_core_http_http_constants_lib": None,
    "quic_core_http_http_decoder_lib": None,
    "quic_core_http_http_encoder_lib": None,
    "quic_core_http_http_frames_lib": None,
    "quic_core_http_metadata_decoder_lib": None,
    "quic_core_http_server_initiated_spdy_stream_lib": None,
    "quic_core_http_spdy_session_lib": None,
    "quic_core_http_spdy_stream_body_manager_lib": None,
    "quic_core_http_spdy_utils_lib": None,
    "quic_core_idle_network_detector_lib": None,
    "quic_core_inlined_string_view_lib": None,
    "quic_core_interval_deque_lib": None,
    "quic_core_mtu_discovery_lib": None,
    "quic_core_network_blackhole_detector_lib": None,
    "quic_core_new_qpack_blocking_manager_lib": None,
    "quic_core_one_block_arena_lib": None,
    "quic_core_packet_creator_lib": None,
    "quic_core_packet_number_indexed_queue_lib": None,
    "quic_core_packets_lib": None,
    "quic_core_path_context_factory_interface_lib": None,
    "quic_core_path_validator_lib": None,
    "quic_core_ping_manager_lib": None,
    "quic_core_process_packet_interface_lib": None,
    "quic_core_qpack_qpack_decoded_headers_accumulator_lib": None,
    "quic_core_qpack_qpack_decoder_lib": None,
    "quic_core_qpack_qpack_decoder_stream_receiver_lib": None,
    "quic_core_qpack_qpack_decoder_stream_sender_lib": None,
    "quic_core_qpack_qpack_encoder_lib": None,
    "quic_core_qpack_qpack_encoder_stream_receiver_lib": None,
    "quic_core_qpack_qpack_encoder_stream_sender_lib": None,
    "quic_core_qpack_qpack_header_table_lib": None,
    "quic_core_qpack_qpack_index_conversions_lib": None,
    "quic_core_qpack_qpack_instruction_decoder_lib": None,
    "quic_core_qpack_qpack_instruction_encoder_lib": None,
    "quic_core_qpack_qpack_instructions_lib": None,
    "quic_core_qpack_qpack_progressive_decoder_lib": None,
    "quic_core_qpack_qpack_required_insert_count_lib": None,
    "quic_core_qpack_qpack_static_table_lib": None,
    "quic_core_qpack_qpack_stream_receiver_lib": None,
    "quic_core_qpack_qpack_stream_sender_delegate_lib": None,
    "quic_core_qpack_qpack_streams_lib": None,
    "quic_core_qpack_value_splitting_header_list_lib": None,
    "quic_core_received_packet_manager_lib": None,
    "quic_core_sent_packet_manager_lib": None,
    "quic_core_server_id_lib": None,
    "quic_core_server_lib": None,
    "quic_core_session_lib": None,
    "quic_core_session_notifier_interface_lib": None,
    "quic_core_socket_address_coder_lib": None,
    "quic_core_stream_frame_data_producer_lib": None,
    "quic_core_stream_send_buffer_inlining_lib": None,
    "quic_core_stream_sequencer_buffer_lib": None,
    "quic_core_sustained_bandwidth_recorder_lib": None,
    "quic_core_time_accumulator_lib": None,
    "quic_core_time_wait_list_manager_lib": None,
    "quic_core_transmission_info_lib": None,
    "quic_core_types_lib": None,
    "quic_core_uber_received_packet_manager_lib": None,
    "quic_core_unacked_packet_map_lib": None,
    "quic_core_utils_lib": None,
    "quic_core_version_manager_lib": None,
    "quic_core_versions_lib": None,
    "quic_core_web_transport_interface_lib": None,
    "quic_force_blockable_packet_writer_lib": None,
    "quic_load_balancer_config_lib": None,
    "quic_load_balancer_encoder_lib": None,
    "quic_server_crypto_crypto_handshake_lib": None,
    "quic_server_crypto_tls_handshake_lib": None,
    "quic_server_http_spdy_session_lib": None,
    "quic_server_session_lib": None,
    "quic_stream_priority_lib": None,
    "quic_test_tools_config_peer_lib": None,
    "quic_test_tools_connection_id_manager_peer_lib": None,
    "quic_test_tools_crypto_server_config_peer_lib": None,
    "quic_test_tools_crypto_stream_peer_lib": None,
    "quic_test_tools_first_flight_lib": None,
    "quic_test_tools_flow_controller_peer_lib": None,
    "quic_test_tools_framer_peer_lib": None,
    "quic_test_tools_interval_deque_peer_lib": None,
    "quic_test_tools_mock_clock_lib": None,
    "quic_test_tools_mock_random_lib": None,
    "quic_test_tools_mock_syscall_wrapper_lib": None,
    "quic_test_tools_qpack_qpack_test_utils_lib": None,
    "quic_test_tools_sent_packet_manager_peer_lib": None,
    "quic_test_tools_server_session_base_peer": None,
    "quic_test_tools_session_peer_lib": None,
    "quic_test_tools_simple_quic_framer_lib": None,
    "quic_test_tools_stream_peer_lib": None,
    "quic_test_tools_test_certificates_lib": None,
    "quic_test_tools_test_utils_lib": None,
    "quic_test_tools_unacked_packet_map_peer_lib": None,
    "quiche_common_mem_slice_storage": None,
}

def _expand_external_deps(external_deps):
    result = []
    for dep in external_deps:
        if dep not in _EXTERNAL_DEPS:
            fail("unsupported external_dep for bazel-registry quiche overlay: %s" % dep)
        result += _EXTERNAL_DEPS[dep]
    return result

def _http3_gate(name, xs):
    # QUIC/HTTP3-only targets contribute nothing when HTTP/3 is disabled, matching
    # Envoy's envoy_select_enable_http3 in WORKSPACE mode. Non-QUIC targets and
    # empty attributes are returned unchanged.
    if not xs or name not in _HTTP3_ONLY_LIBS:
        return xs
    return select({
        "//:disable_http3": [],
        "//conditions:default": xs,
    })

def quiche_cc_library(name, srcs = [], hdrs = [], deps = [], visibility = ["//visibility:public"], defines = [], copts = [], external_deps = [], repository = None, tcmalloc_dep = None, hdrs_lib = None, stamped = None, **kwargs):
    cc_library(
        name = name,
        srcs = _http3_gate(name, srcs),
        hdrs = _http3_gate(name, hdrs),
        deps = _http3_gate(name, deps + _expand_external_deps(external_deps)),
        includes = ["."],
        visibility = visibility,
        defines = defines,
        copts = quiche_copts + copts,
        **kwargs
    )

def quiche_cc_test_library(name, srcs = [], hdrs = [], deps = [], visibility = ["//visibility:public"], defines = [], copts = [], external_deps = [], repository = None, tcmalloc_dep = None, hdrs_lib = None, stamped = None, **kwargs):
    cc_library(
        name = name,
        srcs = _http3_gate(name, srcs),
        hdrs = _http3_gate(name, hdrs),
        deps = _http3_gate(name, deps + _expand_external_deps(external_deps)),
        includes = ["."],
        visibility = visibility,
        defines = defines,
        copts = quiche_copts + copts,
        testonly = True,
        **kwargs
    )

def quiche_platform_impl_cc_library(name, srcs = [], hdrs = [], deps = [], visibility = ["//visibility:public"], **kwargs):
    cc_library(
        name = name,
        srcs = srcs,
        hdrs = hdrs,
        deps = deps,
        includes = ["."],
        strip_include_prefix = "quiche/common/platform/default/",
        visibility = visibility,
        **kwargs
    )

def quiche_platform_impl_cc_test_library(name, srcs = [], hdrs = [], deps = [], visibility = ["//visibility:public"], **kwargs):
    cc_library(
        name = name,
        srcs = srcs,
        hdrs = hdrs,
        deps = deps,
        includes = ["."],
        strip_include_prefix = "quiche/common/platform/default/",
        visibility = visibility,
        testonly = True,
        **kwargs
    )
