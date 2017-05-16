AUTOMAKE_OPTIONS=subdir-objects
bin_PROGRAMS=sngrep

sngrep_CFLAGS=
sngrep_LDADD=


sngrep_SOURCES=
sngrep_SOURCES+=capture/capture.c
sngrep_SOURCES+=capture/capture_pcap.c

if USE_EEP
sngrep_SOURCES+=capture/capture_hep.c
endif

if WITH_GNUTLS
sngrep_SOURCES+=packet/packet_tls_gnutls.c
endif

if WITH_OPENSSL
sngrep_SOURCES+=packet/packet_tls_openssl.c
sngrep_CFLAGS+=$(SSL_CFLAGS)
sngrep_LDADD+=$(SSL_LIBS)
endif

sngrep_SOURCES+=packet/address.c
sngrep_SOURCES+=packet/packet.c
sngrep_SOURCES+=packet/packet_link.c
sngrep_SOURCES+=packet/packet_ip.c
sngrep_SOURCES+=packet/packet_tcp.c
sngrep_SOURCES+=packet/packet_udp.c
sngrep_SOURCES+=packet/packet_sip.c
sngrep_SOURCES+=packet/packet_sdp.c
sngrep_SOURCES+=packet/packet_rtp.c
sngrep_SOURCES+=packet/packet_rtcp.c
sngrep_SOURCES+=packet/packet_ws.c
sngrep_SOURCES+=sip.c
sngrep_SOURCES+=sip_call.c
sngrep_SOURCES+=sip_msg.c
sngrep_SOURCES+=sip_attr.c
sngrep_SOURCES+=main.c
sngrep_SOURCES+=option.c
sngrep_SOURCES+=group.c
sngrep_SOURCES+=filter.c
sngrep_SOURCES+=media.c
sngrep_SOURCES+=setting.c
sngrep_SOURCES+=rtp.c
sngrep_SOURCES+=util/util.c
sngrep_SOURCES+=util/hash.c
sngrep_SOURCES+=util/vector.c
sngrep_SOURCES+=util/buffer.c
sngrep_SOURCES+=curses/keybinding.c
sngrep_SOURCES+=curses/ui_panel.c
sngrep_SOURCES+=curses/scrollbar.c
sngrep_SOURCES+=curses/ui_manager.c
sngrep_SOURCES+=curses/panels/ui_call_list.c
sngrep_SOURCES+=curses/panels/ui_call_flow.c
sngrep_SOURCES+=curses/panels/ui_call_raw.c
sngrep_SOURCES+=curses/panels/ui_stats.c
sngrep_SOURCES+=curses/panels/ui_filter.c
sngrep_SOURCES+=curses/panels/ui_save.c
sngrep_SOURCES+=curses/panels/ui_msg_diff.c
sngrep_SOURCES+=curses/panels/ui_column_select.c
sngrep_SOURCES+=curses/panels/ui_settings.c

