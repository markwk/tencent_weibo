<?php
/**
 * 开放平台鉴权类
 * @param 
 * @return
 * @author tuguska
 */
define(MB_RETURN_FORMAT, 'json');

class MBOpenTOAuth {
	public $host = 'http://open.t.qq.com/';
	public $timeout = 30; 
	public $connectTimeout = 30;
	public $sslVerifypeer = FALSE; 
	public $format = MB_RETURN_FORMAT;
	public $decodeJson = TRUE; 
	public $httpInfo; 
	public $userAgent = 'oauth test'; 
	public $decode_json = FALSE; 

    function accessTokenURL()  { return 'https://open.t.qq.com/cgi-bin/access_token'; } 
    function authenticateURL() { return 'http://open.t.qq.com/cgi-bin/authenticate'; } 
    function authorizeURL()    { return 'http://open.t.qq.com/cgi-bin/authorize'; } 
	function requestTokenURL() { return 'https://open.t.qq.com/cgi-bin/request_token'; } 

	function lastStatusCode() { return $this->http_status; } 

    function __construct($consumer_key, $consumer_secret, $oauth_token = NULL, $oauth_token_secret = NULL) { 
        $this->sha1_method = new OAuthSignatureMethod_HMAC_SHA1(); 
        $this->consumer = new OAuthConsumer($consumer_key, $consumer_secret); 
        if (!empty($oauth_token) && !empty($oauth_token_secret)) { 
            $this->token = new OAuthConsumer($oauth_token, $oauth_token_secret); 
        } else { 
            $this->token = NULL; 
        } 
	}

    /** 
     * oauth授权之后的回调页面 
	 * 返回包含 oauth_token 和oauth_token_secret的key/value数组
     */ 
    function getRequestToken($oauth_callback = NULL) { 
        $parameters = array(); 
        if (!empty($oauth_callback)) { 
            $parameters['oauth_callback'] = $oauth_callback; 
        }  

        $request = $this->oAuthRequest($this->requestTokenURL(), 'GET', $parameters); 
		$token = OAuthUtil::parse_parameters($request); 
        $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']); 
        return $token; 
    } 

    /** 
     * 获取授权url
     * @return string 
     */ 
    function getAuthorizeURL($token, $signInWithWeibo = TRUE , $url='') { 
        if (is_array($token)) { 
            $token = $token['oauth_token']; 
        } 
        if (empty($signInWithWeibo)) { 
            return $this->authorizeURL() . "?oauth_token={$token}"; 
        } else { 
            return $this->authenticateURL() . "?oauth_token={$token}"; 
        } 
	} 	

    /** 
	* 交换授权
	* Exchange the request token and secret for an access token and 
     * secret, to sign API calls. 
     * 
     * @return array array("oauth_token" => the access token, 
     *                "oauth_token_secret" => the access secret) 
     */ 
    function getAccessToken($oauth_verifier = FALSE, $oauth_token = false) { 
        $parameters = array(); 
        if (!empty($oauth_verifier)) { 
            $parameters['oauth_verifier'] = $oauth_verifier; 
        } 
		$request = $this->oAuthRequest($this->accessTokenURL(), 'GET', $parameters);
		$token = OAuthUtil::parse_parameters($request); 
        $this->token = new OAuthConsumer($token['oauth_token'], $token['oauth_token_secret']); 
        return $token; 
	} 

	function jsonDecode($response, $assoc=true)	{
		$response = preg_replace('/[^\x20-\xff]*/', "", $response);	
		$jsonArr = json_decode($response, $assoc);
		if(!is_array($jsonArr))
		{
			throw new Exception('格式错误!');
		}
		$ret = $jsonArr["ret"];
		$msg = $jsonArr["msg"];
		/**
		 *Ret=0 成功返回
		 *Ret=1 参数错误
		 *Ret=2 频率受限
		 *Ret=3 鉴权失败
		 *Ret=4 服务器内部错误
		 */
		switch ($ret) {
			case 0:
				return $jsonArr;;
				break;
			case 1:
				throw new Exception('参数错误!');
				break;
			case 2:
				throw new Exception('频率受限!');
				break;
			case 3:
				throw new Exception('鉴权失败!');
				break;
			default:
				$errcode = $jsonArr["errcode"];
				if(isset($errcode))			//统一提示发表失败
				{
					throw new Exception("发表失败");
					break;
					//require_once MB_COMM_DIR.'/api_errcode.class.php';
					//$msg = ApiErrCode::getMsg($errcode);
				}
				throw new Exception('服务器内部错误!');
				break;
		}
	}
	
    /** 
     * 重新封装的get请求. 
     * @return mixed 
     */ 
    function get($url, $parameters) {
		$response = $this->oAuthRequest($url, 'GET', $parameters); 
		if (MB_RETURN_FORMAT === 'json') { 
            return $this->jsonDecode($response, true);
		}
        return $response; 
	}

	 /** 
     * 重新封装的post请求. 
     * @return mixed 
     */ 
    function post($url, $parameters = array() , $multi = false) { 
        $response = $this->oAuthRequest($url, 'POST', $parameters , $multi ); 
		if (MB_RETURN_FORMAT === 'json') { 
            return $this->jsonDecode($response, true); 
        } 
        return $response; 
	}

	 /** 
     * DELTE wrapper for oAuthReqeust. 
     * @return mixed 
     */ 
    function delete($url, $parameters = array()) { 
        $response = $this->oAuthRequest($url, 'DELETE', $parameters); 
		if (MB_RETURN_FORMAT === 'json') { 
            return $this->jsonDecode($response, true); 
        } 
        return $response; 
    } 

    /** 
     * 发送请求的具体类
     * @return string 
     */ 
    function oAuthRequest($url, $method, $parameters , $multi = false) { 
        if (strrpos($url, 'http://') !== 0 && strrpos($url, 'https://') !== 0) { 
            $url = "{$this->host}{$url}.{$this->format}"; 
		}
        $request = OAuthRequest::from_consumer_and_token($this->consumer, $this->token, $method, $url, $parameters); 
		$request->sign_request($this->sha1_method, $this->consumer, $this->token);
        switch ($method) { 
        case 'GET': 
            return $this->http($request->to_url(), 'GET'); 
        default: 
            return $this->http($request->get_normalized_http_url(), $method, $request->to_postdata($multi) , $multi ); 
        } 
	}     

    /*
	function http($url, $method, $postfields = NULL , $multi = false){
		//$https = 0;
		//判断是否是https请求
		if(strrpos($url, 'https://')===0){
			$port = 443;
			$version = '1.1';
			$host = 'ssl://'.MB_API_HOST;	
			
		}else{
			$port = 80;	
			$version = '1.0';
			$host = MB_API_HOST;
		}

		$header = "$method $url HTTP/$version\r\n";	
		$header .= "Host: ".MB_API_HOST."\r\n";
		if($multi){
			$header .= "Content-Type: multipart/form-data; boundary=" . OAuthUtil::$boundary . "\r\n";	
		}else{	
			$header .= "Content-Type: application/x-www-form-urlencoded\r\n";  
		}
		if(strtolower($method) == 'post' ){
			$header .= "Content-Length: ".strlen($postfields)."\r\n";
			$header .= "Connection: Close\r\n\r\n";  
			$header .= $postfields;
		}else{
			$header .= "Connection: Close\r\n\r\n";  
		}

		$ret = '';
		
		$fp = fsockopen($host,$port,$errno,$errstr,30);

		if(!$fp){
			$error = '建立sock连接失败';
			throw new Exception($error);
		}else{
			fwrite ($fp, $header);  
			while (!feof($fp)) {
				$ret .= fgets($fp, 4096);
			}
			fclose($fp);
			if(strrpos($ret,'Transfer-Encoding: chunked')){
				$info = split("\r\n\r\n",$ret);
				$response = split("\r\n",$info[1]);
				$t = array_slice($response,1,-1);

				$returnInfo = implode('',$t);
			}else{
				$response = split("\r\n\r\n",$ret);
				$returnInfo = $response[1];
			}
			//转成utf-8编码
			return iconv("utf-8","utf-8//ignore",$returnInfo);
		}
		
	}*/
 

	function http($url, $method, $postfields = NULL , $multi = false){
        $this->http_info = array(); 
        $ci = curl_init(); 
        curl_setopt($ci, CURLOPT_USERAGENT, $this->userAgent); 
        curl_setopt($ci, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout); 
        curl_setopt($ci, CURLOPT_TIMEOUT, $this->timeout); 
        curl_setopt($ci, CURLOPT_RETURNTRANSFER, TRUE); 
        curl_setopt($ci, CURLOPT_SSL_VERIFYPEER, $this->sslVerifypeer); 
        curl_setopt($ci, CURLOPT_HEADERFUNCTION, array($this, 'getHeader')); 
        curl_setopt($ci, CURLOPT_HEADER, FALSE); 

        switch ($method) { 
        case 'POST': 
            curl_setopt($ci, CURLOPT_POST, TRUE); 
            if (!empty($postfields)) { 
                curl_setopt($ci, CURLOPT_POSTFIELDS, $postfields); 
            } 
            break; 
        case 'DELETE': 
            curl_setopt($ci, CURLOPT_CUSTOMREQUEST, 'DELETE'); 
            if (!empty($postfields)) { 
                $url = "{$url}?{$postfields}"; 
            } 
        } 

        $header_array = array(); 
        $header_array2=array(); 
        if( $multi ) 
        	$header_array2 = array("Content-Type: multipart/form-data; boundary=" . OAuthUtil::$boundary , "Expect: ");
        foreach($header_array as $k => $v) 
            array_push($header_array2,$k.': '.$v); 

        curl_setopt($ci, CURLOPT_HTTPHEADER, $header_array2 ); 
        curl_setopt($ci, CURLINFO_HEADER_OUT, TRUE ); 

        curl_setopt($ci, CURLOPT_URL, $url); 

        $response = curl_exec($ci); 
        $this->http_code = curl_getinfo($ci, CURLINFO_HTTP_CODE); 
        $this->http_info = array_merge($this->http_info, curl_getinfo($ci)); 
        $this->url = $url; 
        curl_close ($ci); 
        return $response; 

	}
	
    function getHeader($ch, $header) { 
        $i = strpos($header, ':'); 
        if (!empty($i)) { 
            $key = str_replace('-', '_', strtolower(substr($header, 0, $i))); 
            $value = trim(substr($header, $i + 2)); 
            $this->http_header[$key] = $value; 
        } 
        return strlen($header); 
	} 
}

/**
 * 开放平台操作类
 * @param 
 * @return
 * @author tuguska
 */

class MBApiClient
{
    /** 
     * 构造函数 
     *  
     * @access public 
     * @param mixed $wbakey 应用APP KEY 
     * @param mixed $wbskey 应用APP SECRET 
     * @param mixed $accecss_token OAuth认证返回的token 
     * @param mixed $accecss_token_secret OAuth认证返回的token secret 
     * @return void 
	 */
	public $host = 'open.t.qq.com';
    function __construct( $wbakey , $wbskey , $accecss_token , $accecss_token_secret ) 
	{
        $this->oauth = new MBOpenTOAuth( $wbakey , $wbskey , $accecss_token , $accecss_token_secret ); 
	}

	/******************
	 * 获取用户消息
     * @access public 
	*@f 分页标识（0：第一页，1：向下翻页，2向上翻页）
	*@t: 本页起始时间（第一页 0，继续：根据返回记录时间决定）
	*@n: 每次请求记录的条数（1-20条）
	*@name: 用户名 空表示本人
	 * *********************/
	public function getTimeline($p){
		if(!isset($p['name'])){
			$url = 'http://open.t.qq.com/api/statuses/home_timeline?f=1';
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'pageflag' => $p['f'],
				'reqnum' => $p['n'],
				'pagetime' =>  $p['t']
			);					
		}else{
			$url = 'http://open.t.qq.com/api/statuses/user_timeline?f=1';
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'pageflag' => $p['f'],
				'reqnum' => $p['n'],
				'pagetime' =>  $p['t'],
				'name' => $p['name']
			);					
		}
	 	return $this->oauth->get($url,$params); 
	}

	/******************
	 * 广播大厅消息
	*@p: 记录的起始位置（第一次请求是填0，继续请求进填上次返回的Pos）
	*@n: 每次请求记录的条数（1-20条）
	 * *********************/
	public function getPublic($p){
		$url = 'http://open.t.qq.com/api/statuses/public_timeline?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'pos' => $p['p'],
			'reqnum' => $p['n']	
		);
	 	return $this->oauth->get($url,$params); 
	}

	/******************
	*获取关于我的消息 
	*@f 分页标识（0：第一页，1：向下翻页，2向上翻页）
	*@t: 本页起始时间（第一页 0，继续：根据返回记录时间决定）
	*@n: 每次请求记录的条数（1-20条）
	*@l: 当前页最后一条记录，用用精确翻页用
	*@type : 0 提及我的, other 我发表的
	**********************/
	public function getMyTweet($p){
		$p['type']==0?$url = 'http://open.t.qq.com/api/statuses/mentions_timeline?f=1':$url = 'http://open.t.qq.com/api/statuses/broadcast_timeline?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'pageflag' => $p['f'],
			'reqnum' => $p['n'],
			'pagetime' => $p['t'],
			'lastid' => $p['l']	
		);
	 	return $this->oauth->get($url,$params); 
	}

	/******************
	*获取话题下的消息
	*@t: 话题名字
	*@f 分页标识（PageFlag = 1表示向后（下一页）查找；PageFlag = 2表示向前（上一页）查找；PageFlag = 3表示跳到最后一页  PageFlag = 4表示跳到最前一页）
	*@p: 分页标识（第一页 填空，继续翻页：根据返回的 pageinfo决定）
	*@n: 每次请求记录的条数（1-20条）
	**********************/
	public function getTopic($p){
		$url = 'http://open.t.qq.com/api/statuses/ht_timeline?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'pageflag' => $p['f'],
			'reqnum' => $p['n'],
			'httext' => $p['t'],
			'pageinfo' => $p['p']
		);
	 	return $this->oauth->get($url,$params); 
	}

	/******************
	*获取一条消息
	*@id: 微博ID
	**********************/
	public function getOne($p){
		$url = 'http://open.t.qq.com/api/t/show?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'id' => $p['id']
		);
	 	return $this->oauth->get($url,$params); 
	}

	/******************
	*发表一条消息
	*@c: 微博内容
	*@ip: 用户IP(以分析用户所在地)
	*@j: 经度（可以填空）
	*@w: 纬度（可以填空）
	*@p: 图片
	*@r: 父id
	*@type: 1 发表 2 转播 3 回复 4 点评
	**********************/
	public function postOne($p){
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'content' => $p['c'],
			'clientip' => $p['ip'],
			'jing' => $p['j'],
			'wei' => $p['w']
		);
		switch($p['type']){
			case 2:
				$url = 'http://open.t.qq.com/api/t/re_add?f=1';
				$params['reid'] = $p['r'];
				return $this->oauth->post($url,$params); 
				break;
			case 3:
				$url = 'http://open.t.qq.com/api/t/reply?f=1';
				$params['reid'] = $p['r'];
				return $this->oauth->post($url,$params); 
				break;
			case 4:
				$url = 'http://open.t.qq.com/api/t/comment?f=1';
				$params['reid'] = $p['r'];
				return $this->oauth->post($url,$params); 
				break;
			default:
				if(!empty($p['p'])){
					$url = 'http://open.t.qq.com/api/t/add_pic?f=1';
					$params['pic'] = $p['p'];
					return $this->oauth->post($url,$params,true); 
				}else{
					$url = 'http://open.t.qq.com/api/t/add?f=1';
					return $this->oauth->post($url,$params); 
				}	
			break;			
		}	

	}

	/******************
	*删除一条消息
	*@id: 微博ID
	**********************/
	public function delOne($p){
		$url = 'http://open.t.qq.com/api/t/del?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'id' => $p['id']
		);
	 	return $this->oauth->post($url,$params); 
	}	

	/******************
	*获取转播和点评消息列表
	*@reid：转发或者回复根结点ID；
	*@f：（根据dwTime），0：第一页，1：向下翻页，2向上翻页；
	*@t：起始时间戳，上下翻页时才有用，取第一页时忽略；
	*@tid：起始id，用于结果查询中的定位，上下翻页时才有用；
	*@n：要返回的记录的条数(1-20)；
	*@Flag:标识0 转播列表，1点评列表 2 点评与转播列表
	**********************/
	public function getReplay($p){
		$url = 'http://open.t.qq.com/api/t/re_list?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'rootid' => $p['reid'],
			'pageflag' => $p['f'],
			'reqnum' => $p['n'],
			'flag' => $p['flag']
		);
		if(isset($p['t'])){
			$params['pagetime'] = $p['t'];	
		}
		if(isset($p['tid'])){
			$params['twitterid'] = $p['tid'];	
		}
	 	return $this->oauth->get($url,$params); 	
	}

	/******************
	*获取当前用户的信息
	*@n:用户名 空表示本人
	**********************/
	public function getUserInfo($p=false){
		if(!$p || !$p['n']){
			$url = 'http://open.t.qq.com/api/user/info?f=1';
			$params = array(
				'format' => MB_RETURN_FORMAT
			);
		}else{
			$url = 'http://open.t.qq.com/api/user/other_info?f=1';
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'name' => $p['n']
			);
		}
	 	return $this->oauth->get($url,$params); 	
	}

	/******************
	*更新用户资料
	*@p 数组,包括以下:
	*@nick: 昵称
	*@sex: 性别 0 ，1：男2：女
	*@year:出生年 1900-2010
	*@month:出生月 1-12
	*@day:出生日 1-31
	*@countrycode:国家码
	*@provincecode:地区码
	*@citycode:城市 码
	*@introduction: 个人介绍
	**********************/
	public function updateMyinfo($p){
		$url = 'http://open.t.qq.com/api/user/update?f=1';
		$p['format'] = MB_RETURN_FORMAT;
	 	return $this->oauth->post($url,$p); 	
	}	

	/******************
	*更新用户头像
	*@Pic:文件域表单名 本字段不能放入到签名串中
	******************/
	public function updateUserHead($p){
		$url = 'http://open.t.qq.com/api/user/update_head?f=1';
		$p['format'] = MB_RETURN_FORMAT;
		return $this->oauth->post($url, $p, true); 	
	}	

	/******************
	*获取听众列表/偶像列表
	*@num: 请求个数(1-30)
	*@start: 起始位置
	*@n:用户名 空表示本人
	*@type: 0 听众 1 偶像
	**********************/
	public function getMyfans($p){
		try{
			if($p['n']  == ''){
				$p['type']?$url = 'http://open.t.qq.com/api/friends/idollist':$url = 'http://open.t.qq.com/api/friends/fanslist';
			}else{
				$p['type']?$url = 'http://open.t.qq.com/api/friends/user_idollist':$url = 'http://open.t.qq.com/api/friends/user_fanslist';
			}
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'name' => $p['n'],
				'reqnum' => $p['num'],
				'startindex' => $p['start']
			);
		 	return $this->oauth->get($url,$params);
		} catch(MBException $e) {
			$ret = array("ret"=>0, "msg"=>"ok"
					, "data"=>array("timestamp"=>0, "hasnext"=>1, "info"=>array()));
			return $ret;
		}
	}

	/******************
	*收听/取消收听某人
	*@n: 用户名
	*@type: 0 取消收听,1 收听 ,2 特别收听
	**********************/	
	public function setMyidol($p){
		switch($p['type']){
			case 0:
				$url = 'http://open.t.qq.com/api/friends/del?f=1';
				break;
			case 1:
				$url = 'http://open.t.qq.com/api/friends/add?f=1';
				break;
			case 2:
				$url = 'http://open.t.qq.com/api/friends/addspecail?f=1';
				break;
		}
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'name' => $p['n']
		);
	 	return $this->oauth->post($url,$params);		
	}
	
	/******************
	*检测是否我粉丝或偶像
	*@n: 其他人的帐户名列表（最多30个,逗号分隔）
	*@flag: 0 检测粉丝，1检测偶像
	**********************/	
	public function checkFriend($p){
		$url = 'http://open.t.qq.com/api/friends/check?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'names' => $p['n'],
			'flag' => $p['type']
		);
		return $this->oauth->get($url,$params);
	}

	/******************
	*发私信
	*@c: 微博内容
	*@ip: 用户IP(以分析用户所在地)
	*@j: 经度（可以填空）
	*@w: 纬度（可以填空）
	*@n: 接收方微博帐号
	**********************/
	public function postOneMail($p){
		$url = 'http://open.t.qq.com/api/private/add?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'content' => $p['c'],
			'clientip' => $p['ip'],
			'jing' => $p['j'],
			'wei' => $p['w'],
			'name' => $p['n']
			);
		return $this->oauth->post($url,$params); 
	}
	
	/******************
	*删除一封私信
	*@id: 微博ID
	**********************/
	public function delOneMail($p){
		$url = 'http://open.t.qq.com/api/private/del?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'id' => $p['id']
		);
	 	return $this->oauth->post($url,$params); 
	}
	
	/******************
	*私信收件箱和发件箱
	*@f 分页标识（0：第一页，1：向下翻页，2向上翻页）
	*@t: 本页起始时间（第一页 0，继续：根据返回记录时间决定）
	*@n: 每次请求记录的条数（1-20条）
	*@type : 0 发件箱 1 收件箱
	**********************/	
	public function getMailBox($p){
		if($p['type']){
			$url = 'http://open.t.qq.com/api/private/recv?f=1';
		}else{
			$url = 'http://open.t.qq.com/api/private/send?f=1';
		}
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'pageflag' => $p['f'],
			'pagetime' => $p['t'],
			'reqnum' => $p['n']
		);
	 	return $this->oauth->get($url,$params);		
	}	

	/******************
	*搜索
	*@k:搜索关键字
	*@n: 每页大小
	*@p: 页码
	*@type : 0 用户 1 消息 2 话题 
	**********************/	
	public function getSearch($p){
		switch($p['type']){
			case 0:
				$url = 'http://open.t.qq.com/api/search/user?f=1';
				break;
			case 1:
				$url = 'http://open.t.qq.com/api/search/t?f=1';
				break;
			case 2:
				$url = 'http://open.t.qq.com/api/search/ht?f=1';
				break;
			default:
				$url = 'http://open.t.qq.com/api/search/t?f=1';
				break;
		}		

		$params = array(
			'format' => MB_RETURN_FORMAT,
			'keyword' => $p['k'],
			'pagesize' => $p['n'],
			'page' => $p['p']
		);
	 	return $this->oauth->get($url,$params);		
	}	

	/******************
	*热门话题
	*@type: 请求类型 1 话题名，2 搜索关键字 3 两种类型都有
	*@n: 请求个数（最多20）
	*@Pos :请求位置，第一次请求时填0，继续填上次返回的POS
	**********************/	
	public function getHotTopic($p){
		$url = 'http://open.t.qq.com/api/trends/ht?f=1';
		if($p['type']<1 || $p['type']>3){
			$p['type'] = 1;
		}
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'type' => $p['type'],
			'reqnum' => $p['n'],
			'pos' => $p['pos']
		);
	 	return $this->oauth->get($url,$params);		
	}			

	/******************
	*查看数据更新条数
	*@op :请求类型 0：只请求更新数，不清除更新数，1：请求更新数，并对更新数清零
	*@type：5 首页未读消息记数，6 @页消息记数 7 私信页消息计数 8 新增粉丝数 9 首页广播数（原创的）
	**********************/	
	public function getUpdate($p){
		$url = 'http://open.t.qq.com/api/info/update?f=1';
		if(isset($p['type'])){
			if($p['op']){
				$params = array(
					'format' => MB_RETURN_FORMAT,
					'op' => $p['op'],
					'type' => $p['type']
				);			
			}else{
				$params = array(
					'format' => MB_RETURN_FORMAT,
					'op' => $p['op']
				);			
			}
		}else{
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'op' => $p['op']
			);
		}
	 	return $this->oauth->get($url,$params);		
	}	

	/******************
	*添加/删除 收藏的微博
	*@id : 微博id
	*@type：1 添加 0 删除
	**********************/	
	public function postFavMsg($p){
		if($p['type']){
			$url = 'http://open.t.qq.com/api/fav/addt?f=1';
		}else{
			$url = 'http://open.t.qq.com/api/fav/delt?f=1';
		}
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'id' => $p['id']
		);
	 	return $this->oauth->post($url,$params);		
	}

	/******************
	*添加/删除 收藏的话题
	*@id : 微博id
	*@type：1 添加 0 删除
	**********************/	
	public function postFavTopic($p){
		if($p['type']){
			$url = 'http://open.t.qq.com/api/fav/addht?f=1';
		}else{
			$url = 'http://open.t.qq.com/api/fav/delht?f=1';
		}
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'id' => $p['id']
		);
	 	return $this->oauth->post($url,$params);		
	}	

	/******************
	*获取收藏的内容
	*******话题
	n:请求数，最多15
	f:翻页标识  0：首页   1：向下翻页 2：向上翻页
	t:翻页时间戳0
	lid:翻页话题ID，第次请求时为0
	*******消息
	f 分页标识（0：第一页，1：向下翻页，2向上翻页）
	t: 本页起始时间（第一页 0，继续：根据返回记录时间决定）
	n: 每次请求记录的条数（1-20条）
	*@type 0 收藏的消息  1 收藏的话题
	**********************/	
	public function getFav($p){
		if($p['type']){
			$url = 'http://open.t.qq.com/api/fav/list_ht?f=1';
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'reqnum' => $p['n'],		
				'pageflag' => $p['f'],		
				'pagetime' => $p['t'],		
				'lastid' => $p['lid']		
				);
		}else{
			$url = 'http://open.t.qq.com/api/fav/list_t?f=1';	
			$params = array(
				'format' => MB_RETURN_FORMAT,
				'reqnum' => $p['n'],		
				'pageflag' => $p['f'],		
				'pagetime' => $p['t']		
				);
		}
	 	return $this->oauth->get($url,$params);		
	}

	/******************
	*获取话题id
	*@list: 话题名字列表（abc,efg,）
	**********************/	
	public function getTopicId($p){
			$url = 'http://open.t.qq.com/api/ht/ids?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'httexts' => $p['list']
		);
	 	return $this->oauth->get($url,$params);		
	}	

	/******************
	*获取话题内容
	*@list: 话题id列表（abc,efg,）
	**********************/	
	public function getTopicList($p){
			$url = 'http://open.t.qq.com/api/ht/info?f=1';
		$params = array(
			'format' => MB_RETURN_FORMAT,
			'ids' => $p['list']
		);
	 	return $this->oauth->get($url,$params);		
	}		
}
?>