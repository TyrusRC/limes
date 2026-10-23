location / {
    proxy_read_timeout                          300;
    proxy_connect_timeout                       300;
    proxy_redirect                              off;

    proxy_set_header                            Host $host;
    proxy_set_header                            X-Real-IP $remote_addr;
    proxy_set_header                            X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header                            X-Forwarded-Proto $scheme;
    # Re-resolve the app through Docker DNS: a recreated web container gets
    # a new IP, and a static upstream would keep the old one (502s).
    resolver                                    127.0.0.11 valid=10s ipv6=off;
    set $limes_upstream                         limes:8000;
    proxy_pass                                  http://$limes_upstream;
}

# MCP server (optional compose profile `mcp`). The variable proxy_pass lets nginx start without the service;
# while it is off (502) the answer is a plain 404; a 504 stays a 504.
location = /mcp {
    proxy_read_timeout                          300;
    proxy_connect_timeout                       300;
    proxy_redirect                              off;

    proxy_set_header                            Host $host;
    proxy_set_header                            X-Real-IP $remote_addr;
    proxy_set_header                            X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header                            X-Forwarded-Proto $scheme;
    resolver                                    127.0.0.11 valid=10s ipv6=off;
    set $limes_mcp_upstream                     mcp:8001;
    proxy_pass                                  http://$limes_mcp_upstream;
    proxy_http_version                          1.1;
    proxy_set_header                            Connection "";
    proxy_buffering                             off;
    client_max_body_size                        1m;
    limit_req                                   zone=mcp burst=40 nodelay;
    limit_req_status                            429;
    access_log                                  /dev/stdout mcp;
    error_page                                  502 = @mcp_off;
}

location @mcp_off {
    access_log                                  /dev/stdout mcp;
    default_type                                text/plain;
    return                                      404 "MCP is not enabled on this instance\n";
}

location /staticfiles/ {
    alias /usr/src/app/staticfiles/;
}

location /protected_media/ {
    internal;
    alias /usr/src/scan_results/;
    autoindex off;
}
