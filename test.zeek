global cntTable :table[addr] of int = table();
global ipTable :table[addr] of set[string] = table();
event http_reply(c: connection, version: string, code: count, reason: string){
	local ua :string = c$http$user_agent;
	local ip :addr = c$id$orig_h;
	if (ip in ipTable){
		if(ua !in ipTable[ip]){
			add (ipTable[ip])[ua];
			cntTable[ip] += 1;
		}
	}
	else{
		ipTable[ip] = set(ua);
		cntTable[ip] = 1;
	}
}

event zeek_done()
{
	for(ip,cnt in cntTable)
	{
		if(cnt >= 3)
		{
			print(fmt("%s is a proxy", ip));
		}
	}
}