# oauth_module
OAuth2.0 Worker 모듈

### 수정해야하는 부분
wrangler.jsonc


### bindings

"vars" :{
		"SUPABASE_URL":"",
		"ALLOWED_REDIRECT_ORIGINS":"",
		}

SUPABASE_ANON_KEY, ENCRYPTION_KEY 등 민감한 값은


### KV namespaces
 "kv_namespaces": [
		{
		"binding": "KV_SESSIONS",
		"id": "가나다라마바사"
		}
	]
	
wrangler kv:namespace create KV_SESSIONS  ← KV 새로 생성
id는 wrangler kv:namespace list 명령어로 확인 후 입력
기존에 "kv_namespaces"를 만들어놓으면 명령어가 작동하지 않음.
KV namespaces 삭제 방법 : wrangler kv namespace delete --namespace-id <ID>
