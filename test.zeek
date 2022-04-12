global proxy_table: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string){
	if(c$http?$user_agent){
		local origin_addr = c$id$orig_h;
		local user_agent = to_lower(c$http$user_agent);
		if(origin_addr in proxy_table){
			add proxy_table[origin_addr][user_agent];
		}else{
			proxy_table[origin_addr] = set(user_agent);
		}
	}
}

event zeek_done()
{
	for(origin_addr in proxy_table){
		if(|proxy_table[origin_addr]| >= 3){
			print fmt("%s is a proxy", origin_addr);
		}
	}
}