use crate::src::ffi_alias::type_alias::*;
use crate::src::ffi_struct::struct_define::*;

extern "C" {
    // ftp.rs

    // ftplistparser.rs

    // http_aws_sigv4.rs

    // http_chunks.rs
    pub fn Curl_isxdigit(c: libc::c_int) -> libc::c_int;
    pub fn Curl_dyn_init(s: *mut dynbuf, toobig: size_t);
    pub fn Curl_dyn_addn(s: *mut dynbuf, mem: *const libc::c_void, len: size_t) -> CURLcode;
    pub fn Curl_dyn_reset(s: *mut dynbuf);
    pub fn Curl_dyn_ptr(s: *const dynbuf) -> *mut libc::c_char;
    pub fn Curl_dyn_len(s: *const dynbuf) -> size_t;
    pub fn Curl_dyn_add(s: *mut dynbuf, str: *const libc::c_char) -> CURLcode;
    // fn Curl_client_write(
    //     data: *mut Curl_easy,
    //     type_0: libc::c_int,
    //     ptr: *mut libc::c_char,
    //     len: size_t,
    // ) -> CURLcode;
    // fn Curl_unencode_write(
    //     data: *mut Curl_easy,
    //     writer: *mut contenc_writer,
    //     buf: *const libc::c_char,
    //     nbytes: size_t,
    // ) -> CURLcode;
    pub fn curlx_strtoofft(
        str: *const libc::c_char,
        endp: *mut *mut libc::c_char,
        base: libc::c_int,
        num: *mut curl_off_t,
    ) -> CURLofft;
    pub fn curlx_sotouz(sonum: curl_off_t) -> size_t;
    // http_digest.rs

    // http_negotiate.rs

    // http_ntlm.rs
    pub fn curl_strnequal(
        s1: *const libc::c_char,
        s2: *const libc::c_char,
        n: size_t,
    ) -> libc::c_int;
    pub fn Curl_isspace(c: libc::c_int) -> libc::c_int;
    pub fn curl_free(p: *mut libc::c_void);
    pub fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    pub fn Curl_infof(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    pub fn Curl_http_auth_cleanup_ntlm_wb(conn: *mut connectdata);
    pub fn Curl_base64_encode(
        data: *mut Curl_easy,
        inputbuff: *const libc::c_char,
        insize: size_t,
        outptr: *mut *mut libc::c_char,
        outlen: *mut size_t,
    ) -> CURLcode;
    pub fn Curl_base64_decode(
        src: *const libc::c_char,
        outptr: *mut *mut libc::c_uchar,
        outlen: *mut size_t,
    ) -> CURLcode;
    pub fn Curl_auth_create_ntlm_type1_message(
        data: *mut Curl_easy,
        userp: *const libc::c_char,
        passwdp: *const libc::c_char,
        service: *const libc::c_char,
        host: *const libc::c_char,
        ntlm: *mut ntlmdata,
        out: *mut bufref,
    ) -> CURLcode;
    pub fn Curl_auth_decode_ntlm_type2_message(
        data: *mut Curl_easy,
        type2: *const bufref,
        ntlm: *mut ntlmdata,
    ) -> CURLcode;
    pub fn Curl_auth_create_ntlm_type3_message(
        data: *mut Curl_easy,
        userp: *const libc::c_char,
        passwdp: *const libc::c_char,
        ntlm: *mut ntlmdata,
        out: *mut bufref,
    ) -> CURLcode;
    pub fn Curl_bufref_init(br: *mut bufref);
    pub fn Curl_bufref_set(
        br: *mut bufref,
        ptr: *const libc::c_void,
        len: size_t,
        dtor: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    );
    pub fn Curl_bufref_ptr(br: *const bufref) -> *const libc::c_uchar;
    pub fn Curl_bufref_len(br: *const bufref) -> size_t;
    pub fn Curl_bufref_free(br: *mut bufref);
    pub fn Curl_auth_cleanup_ntlm(ntlm: *mut ntlmdata);
    pub fn curl_maprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
    // http_proxy.rs
    pub fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    pub fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    pub fn Curl_httpchunk_init(data: *mut Curl_easy);
    pub fn Curl_httpchunk_read(
        data: *mut Curl_easy,
        datap: *mut libc::c_char,
        length: ssize_t,
        wrote: *mut ssize_t,
        passthru: *mut CURLcode,
    ) -> CHUNKcode;
    pub fn Curl_dyn_free(s: *mut dynbuf);
    pub fn Curl_dyn_addf(s: *mut dynbuf, fmt: *const libc::c_char, _: ...) -> CURLcode;
    pub fn Curl_compareheader(
        headerline: *const libc::c_char,
        header: *const libc::c_char,
        content: *const libc::c_char,
    ) -> bool;
    pub fn Curl_copy_header_value(header: *const libc::c_char) -> *mut libc::c_char;
    pub fn Curl_checkProxyheaders(
        data: *mut Curl_easy,
        conn: *const connectdata,
        thisheader: *const libc::c_char,
    ) -> *mut libc::c_char;
    pub fn Curl_buffer_send(
        in_0: *mut dynbuf,
        data: *mut Curl_easy,
        bytes_written: *mut curl_off_t,
        included_body_bytes: curl_off_t,
        socketindex: libc::c_int,
    ) -> CURLcode;
    pub fn Curl_add_custom_headers(
        data: *mut Curl_easy,
        is_connect: bool,
        req: *mut dynbuf,
    ) -> CURLcode;
    pub fn Curl_http_input_auth(
        data: *mut Curl_easy,
        proxy: bool,
        auth: *const libc::c_char,
    ) -> CURLcode;
    pub fn Curl_http_auth_act(data: *mut Curl_easy) -> CURLcode;
    pub fn Curl_http_output_auth(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        request: *const libc::c_char,
        httpreq: Curl_HttpReq,
        path: *const libc::c_char,
        proxytunnel: bool,
    ) -> CURLcode;
    pub fn Curl_failf(_: *mut Curl_easy, fmt: *const libc::c_char, _: ...);
    pub fn Curl_client_write(
        data: *mut Curl_easy,
        type_0: libc::c_int,
        ptr: *mut libc::c_char,
        len: size_t,
    ) -> CURLcode;
    pub fn Curl_read(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        buf: *mut libc::c_char,
        buffersize: size_t,
        n: *mut ssize_t,
    ) -> CURLcode;
    pub fn Curl_write(
        data: *mut Curl_easy,
        sockfd: curl_socket_t,
        mem: *const libc::c_void,
        len: size_t,
        written: *mut ssize_t,
    ) -> CURLcode;
    pub fn Curl_debug(
        data: *mut Curl_easy,
        type_0: curl_infotype,
        ptr: *mut libc::c_char,
        size: size_t,
    ) -> libc::c_int;
    pub fn Curl_pgrsUpdate(data: *mut Curl_easy) -> libc::c_int;
    pub fn Curl_timeleft(data: *mut Curl_easy, nowp: *mut curltime, duringconnect: bool) -> timediff_t;
    pub fn Curl_closesocket(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        sock: curl_socket_t,
    ) -> libc::c_int;
    pub fn Curl_conncontrol(conn: *mut connectdata, closeit: libc::c_int);
    pub fn Curl_conn_data_pending(conn: *mut connectdata, sockindex: libc::c_int) -> bool;
    pub fn Curl_fillreadbuffer(data: *mut Curl_easy, bytes: size_t, nreadp: *mut size_t) -> CURLcode;
    pub fn Curl_get_upload_buffer(data: *mut Curl_easy) -> CURLcode;
    // http.rs

    // http2.rs
    pub fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    pub fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    pub fn curl_easy_duphandle(curl: *mut CURL) -> *mut CURL;
    pub fn curl_url() -> *mut CURLU;
    pub fn curl_url_cleanup(handle: *mut CURLU);
    pub fn curl_url_get(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *mut *mut libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    pub fn curl_url_set(
        handle: *mut CURLU,
        what: CURLUPart,
        part: *const libc::c_char,
        flags: libc::c_uint,
    ) -> CURLUcode;
    pub fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
        -> *mut libc::c_void;
    pub fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    pub fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    pub fn nghttp2_session_callbacks_new(
        callbacks_ptr: *mut *mut nghttp2_session_callbacks,
    ) -> libc::c_int;
    pub fn nghttp2_session_callbacks_del(callbacks: *mut nghttp2_session_callbacks);
    pub fn nghttp2_session_callbacks_set_send_callback(
        cbs: *mut nghttp2_session_callbacks,
        send_callback_0: nghttp2_send_callback,
    );
    pub fn nghttp2_session_callbacks_set_on_frame_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_frame_recv_callback: nghttp2_on_frame_recv_callback,
    );
    pub fn nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_data_chunk_recv_callback: nghttp2_on_data_chunk_recv_callback,
    );
    pub fn nghttp2_session_callbacks_set_on_stream_close_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_stream_close_callback: nghttp2_on_stream_close_callback,
    );
    pub fn nghttp2_session_callbacks_set_on_begin_headers_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_begin_headers_callback: nghttp2_on_begin_headers_callback,
    );
    pub fn nghttp2_session_callbacks_set_on_header_callback(
        cbs: *mut nghttp2_session_callbacks,
        on_header_callback: nghttp2_on_header_callback,
    );
    pub fn nghttp2_session_callbacks_set_error_callback(
        cbs: *mut nghttp2_session_callbacks,
        error_callback_0: nghttp2_error_callback,
    );
    pub fn nghttp2_session_client_new(
        session_ptr: *mut *mut nghttp2_session,
        callbacks: *const nghttp2_session_callbacks,
        user_data: *mut libc::c_void,
    ) -> libc::c_int;
    pub fn nghttp2_session_del(session: *mut nghttp2_session);
    pub fn nghttp2_session_send(session: *mut nghttp2_session) -> libc::c_int;
    pub fn nghttp2_session_mem_recv(
        session: *mut nghttp2_session,
        in_0: *const uint8_t,
        inlen: size_t,
    ) -> ssize_t;
    pub fn nghttp2_session_resume_data(
        session: *mut nghttp2_session,
        stream_id: int32_t,
    ) -> libc::c_int;
    pub fn nghttp2_session_want_read(session: *mut nghttp2_session) -> libc::c_int;
    pub fn nghttp2_session_want_write(session: *mut nghttp2_session) -> libc::c_int;
    pub fn nghttp2_session_get_stream_user_data(
        session: *mut nghttp2_session,
        stream_id: int32_t,
    ) -> *mut libc::c_void;
    pub fn nghttp2_session_set_stream_user_data(
        session: *mut nghttp2_session,
        stream_id: int32_t,
        stream_user_data: *mut libc::c_void,
    ) -> libc::c_int;
    pub fn nghttp2_session_get_remote_settings(
        session: *mut nghttp2_session,
        id: nghttp2_settings_id,
    ) -> uint32_t;
    pub fn nghttp2_session_upgrade2(
        session: *mut nghttp2_session,
        settings_payload: *const uint8_t,
        settings_payloadlen: size_t,
        head_request: libc::c_int,
        stream_user_data: *mut libc::c_void,
    ) -> libc::c_int;
    pub fn nghttp2_pack_settings_payload(
        buf: *mut uint8_t,
        buflen: size_t,
        iv: *const nghttp2_settings_entry,
        niv: size_t,
    ) -> ssize_t;
    pub fn nghttp2_strerror(lib_error_code: libc::c_int) -> *const libc::c_char;
    pub fn nghttp2_http2_strerror(error_code: uint32_t) -> *const libc::c_char;
    pub fn nghttp2_priority_spec_init(
        pri_spec: *mut nghttp2_priority_spec,
        stream_id: int32_t,
        weight: int32_t,
        exclusive: libc::c_int,
    );
    pub fn nghttp2_submit_request(
        session: *mut nghttp2_session,
        pri_spec: *const nghttp2_priority_spec,
        nva: *const nghttp2_nv,
        nvlen: size_t,
        data_prd: *const nghttp2_data_provider,
        stream_user_data: *mut libc::c_void,
    ) -> int32_t;
    pub fn nghttp2_submit_priority(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        pri_spec: *const nghttp2_priority_spec,
    ) -> libc::c_int;
    pub fn nghttp2_submit_rst_stream(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        error_code: uint32_t,
    ) -> libc::c_int;
    pub fn nghttp2_submit_settings(
        session: *mut nghttp2_session,
        flags: uint8_t,
        iv: *const nghttp2_settings_entry,
        niv: size_t,
    ) -> libc::c_int;
    pub fn nghttp2_submit_ping(
        session: *mut nghttp2_session,
        flags: uint8_t,
        opaque_data: *const uint8_t,
    ) -> libc::c_int;
    pub fn nghttp2_session_check_request_allowed(session: *mut nghttp2_session) -> libc::c_int;
    pub fn nghttp2_session_set_local_window_size(
        session: *mut nghttp2_session,
        flags: uint8_t,
        stream_id: int32_t,
        window_size: int32_t,
    ) -> libc::c_int;
    pub fn nghttp2_version(least_version: libc::c_int) -> *mut nghttp2_info;
    pub fn nghttp2_is_fatal(lib_error_code: libc::c_int) -> libc::c_int;
    pub fn Curl_now() -> curltime;
    pub fn Curl_timediff(t1: curltime, t2: curltime) -> timediff_t;
    pub fn Curl_http(data: *mut Curl_easy, done: *mut bool) -> CURLcode;
    pub fn Curl_http_done(data: *mut Curl_easy, _: CURLcode, premature: bool) -> CURLcode;
    pub fn Curl_socket_check(
        readfd: curl_socket_t,
        readfd2: curl_socket_t,
        writefd: curl_socket_t,
        timeout_ms: timediff_t,
    ) -> libc::c_int;
    pub fn Curl_base64url_encode(
        data: *mut Curl_easy,
        inputbuff: *const libc::c_char,
        insize: size_t,
        outptr: *mut *mut libc::c_char,
        outlen: *mut size_t,
    ) -> CURLcode;
    pub fn Curl_strcasecompare(first: *const libc::c_char, second: *const libc::c_char) -> libc::c_int;
    pub fn Curl_strncasecompare(
        first: *const libc::c_char,
        second: *const libc::c_char,
        max: size_t,
    ) -> libc::c_int;
    pub fn Curl_strntolower(dest: *mut libc::c_char, src: *const libc::c_char, n: size_t);
    pub fn Curl_expire(data: *mut Curl_easy, milli: timediff_t, _: expire_id);
    pub fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    pub fn Curl_multi_add_perform(
        multi: *mut Curl_multi,
        data: *mut Curl_easy,
        conn: *mut connectdata,
    ) -> CURLMcode;
    pub fn Curl_multi_max_concurrent_streams(multi: *mut Curl_multi) -> libc::c_uint;
    pub fn Curl_close(datap: *mut *mut Curl_easy) -> CURLcode;
    pub fn Curl_connalive(conn: *mut connectdata) -> bool;
    pub fn Curl_saferealloc(ptr: *mut libc::c_void, size: size_t) -> *mut libc::c_void;
    pub fn curl_msnprintf(
        buffer: *mut libc::c_char,
        maxlength: size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    // vtls/bearssl.rs

    // vtls/gskit.rs

    // vtls/gtls.rs

    // vtls/keylog.rs
    pub fn curl_getenv(variable: *const libc::c_char) -> *mut libc::c_char;
    // fn fclose(__stream: *mut FILE) -> libc::c_int;
    // fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    // fn setvbuf(
    //     __stream: *mut FILE,
    //     __buf: *mut libc::c_char,
    //     __modes: libc::c_int,
    //     __n: size_t,
    // ) -> libc::c_int;
    pub fn fputs(__s: *const libc::c_char, __stream: *mut FILE) -> libc::c_int;
    pub fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    // vtls/mbedtls_threadlock.rs

    // vtls/mbedtls.rs

    // vtls/mesalink.rs

    // vtls/nss.rs

    // vtls/openssl.rs

    // vtls/rustls.rs

    // vtls/schannel_verify.rs

    // vtls/schannel.rs

    // vtls/sectransp.rs

    // vtls/vtls.rs

    // vtls/wolfssl.rs

}
