package labs.tierseven.broadsoft.cap
{
	//--------------------------------------------------------------------------
	//
	//  Imports
	//
	//--------------------------------------------------------------------------
	import com.adobe.utils.StringUtil;
	import com.hurlant.crypto.hash.MD5;
	import com.hurlant.crypto.hash.SHA1;
	import com.hurlant.crypto.tls.TLSSocket;
	import com.hurlant.util.Hex;
	import com.sourcestream.flex.http.HttpEvent;
	import com.sourcestream.flex.http.HttpResponse;
	import com.sourcestream.flex.http.RestHttpService;
	
	import flash.events.Event;
	import flash.events.EventDispatcher;
	import flash.events.IOErrorEvent;
	import flash.events.ProgressEvent;
	import flash.events.SecurityErrorEvent;
	import flash.net.Socket;
	import flash.system.Security;
	import flash.utils.ByteArray;
	
	import labs.tierseven.broadsoft.cap.http.BroadsoftServiceEvent;
	import labs.tierseven.broadsoft.cap.http.CallError;
	import labs.tierseven.broadsoft.cap.http.CallUpdate;
	import labs.tierseven.broadsoft.cap.http.XMLResponse;
	
	import mx.utils.Base64Encoder;
	
	/**
	 * This class is designed to connect to and parse data from the broadsoft
	 * CAP API. A persistant socket connection is created to parse all
	 * incoming and outgoing messages.
	 *
	 * @author Jonathan Broquist
	 * @modified Feb 25, 2010
	 */
	public class BroadsoftService extends EventDispatcher
	{
		//--------------------------------------------------------------------------
		//
		//  Variables
		//
		//--------------------------------------------------------------------------
		private var _userId:String;
		private var _username:String;
		private var _password:String;
		private var _server:String;
		private var _port:Number;
		private var _secure:Boolean;
		private var _currentCallId:String;
		private var _applicationId:String;
		private var _nonce:String;
		private var _userUID:String;
		
		private var _serv:RestHttpService;
		
		private var _socket:Socket;
		private var _secureSocket:TLSSocket;
		private var _body:String;
		private var _policyFileLoaded:Boolean;
		private var _newSocketEachRequest:Boolean;
		private var _policyFilePort:int;
		private var _contentType:String;
		private var _rawResponse:String;
		private var _resource:String;
		
		private static const DAYS:Array = new Array("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
		private static const MONTHS:Array = new Array("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
			"Oct", "Nov", "Dec");
		
		public static const EVENT_RESULT:String = "result";
		public static const EVENT_FAULT:String = "fault";
		
		//--------------------------------------------------------------------------
		//
		//  Constructor
		//
		//--------------------------------------------------------------------------
		/**
		 * Constructor definition.
		 */
		public function BroadsoftService(server:String=null, port:Number=0, 
										 secure:Boolean=false, username:String=null, 
										 password:String=null)
		{
			//Set Initialization Properties
			_server = server;
			_port = port;
			_secure = secure;
			_username = username;
			_password = password;
			
			//Initialize RestHttpService
			_serv = new RestHttpService();
		}
		
		//--------------------------------------------------------------------------
		//
		//  Methods
		//
		//--------------------------------------------------------------------------
		public function connect():void
		{
			//Register Authentication
			registerAuthentication();
		}
		
		private function send(body:String=null):void
		{
			_body = body;
			createSocket();
			
			if (_secure)
			{
				_secureSocket.connect(_server, _port);
			}
			else
			{
				_socket.connect(_server, _port);
			}
		}
		
		private function sendRequest(body:String):void
		{
			//Set request XML body
			_body = body;
			
			//Send request to server
			if(secure)
			{
				_secureSocket.writeUTFBytes(_body);
				_secureSocket.flush();
			}
			else
			{
				_socket.writeUTFBytes(_body);
				_socket.flush();
			}
		}
		
		private function createSocket():void
		{
			if (_server != null && _port != 0)
			{
				if (_policyFilePort > 0 && !_policyFileLoaded)
				{
					loadPolicyFile(_server, _policyFilePort);
					_policyFileLoaded = true;
				}
				
				if (_secure)
				{
					if (_newSocketEachRequest || _secureSocket == null)
					{
						_secureSocket = new TLSSocket();
						_secureSocket.addEventListener(Event.CONNECT, connectHandler);
						_secureSocket.addEventListener(Event.CLOSE, closeHandler);
						_secureSocket.addEventListener(ProgressEvent.SOCKET_DATA, dataHandler);
						_secureSocket.addEventListener(IOErrorEvent.IO_ERROR, ioErrorHandler);
						_secureSocket.addEventListener(SecurityErrorEvent.SECURITY_ERROR, securityErrorHandler);
					}
				}
				else if (_newSocketEachRequest || _socket == null)
				{
					_socket = new Socket();
					_socket.addEventListener(Event.CONNECT, connectHandler);
					_socket.addEventListener(Event.CLOSE, closeHandler);
					_socket.addEventListener(ProgressEvent.SOCKET_DATA, dataHandler);
					_socket.addEventListener(IOErrorEvent.IO_ERROR, ioErrorHandler);
					_socket.addEventListener(SecurityErrorEvent.SECURITY_ERROR, securityErrorHandler);
				}
			}
		}
		
		/**
		 * Before establishing socket connections from a flash application, a socket policy file must be loaded from the
		 * target server (i.e., the server hosting the REST service). If the client has not already loaded such a
		 * policy file, this can be accomplished by calling this convenience method. This call is not necessary if the
		 * socket policy file is being served from port 843 (the well-known port for Flash policy files).
		 *
		 * @see http://www.adobe.com/devnet/flashplayer/articles/socket_policy_files.html
		 *
		 * @param server Server hosting the REST service
		 * @param policyFilePort Port on which the server is listening for policy file requests
		 */
		public static function loadPolicyFile(server:String, policyFilePort:int):void
		{
			Security.loadPolicyFile("xmlsocket://" + server + ":" + policyFilePort);
		}
		
		private function encryptPassword():String
		{
			//Initialize Cypto Objects
			var md5:MD5 = new MD5();
			var sha1:SHA1 = new SHA1();
			var hex:Hex = new Hex();
			
			//Encrypt Password (SHA1)
			var _encryptedPass:ByteArray = sha1.hash(Hex.toArray(Hex.fromString(_password)));
			var encryptedPass:String = Hex.fromArray(_encryptedPass);
			
			//Encrypt Password with nonce [MD5(nonce : encryptedPassword)]
			var _password:ByteArray = md5.hash(Hex.toArray(Hex.fromString(_nonce +":"+ encryptedPass)));
			
			return Hex.fromArray(_password);
		}
		
		private function registerAuthentication():void
		{
			var dataHeader:String = '<?xml version="1.0" encoding="UTF-8"?>';
			var node:XML = 
				<BroadsoftDocument protocol="CAP" version="14.0">
					<command commandType="registerAuthentication">
						<commandData>
							<user userType="CallClient">
								<id>{_userId}</id>
								<applicationId>{applicationId}</applicationId>
							</user>
						</commandData>
					</command>
				</BroadsoftDocument>;
			
			var request:String = dataHeader + node.toXMLString();
			//trace(request);
			
			trace("--Registering Authentication--");
			send(request);
		}
		
		private function registerRequest():void
		{
			//Get encrypted password
			var encryptedPassword:String = encryptPassword();
			
			//Create XML
			var dataHeader:String = '<?xml version="1.0" encoding="UTF-8"?>';
			var node:XML = 
				<BroadsoftDocument protocol="CAP" version="14.0">
					<command commandType="registerRequest">
						<commandData>
							<user userType="CallClient">
								<id>{_userId}</id>
								<securePassword>{encryptedPassword}</securePassword>
								<applicationId>{applicationId}</applicationId>
							</user>
						</commandData>
					</command>
				</BroadsoftDocument>;
			
			var request:String = dataHeader +"\n" + node.toXMLString();
			//trace(request);
			
			//Send request to server
			trace("--Registering Request--");
			sendRequest(request);
		}
		
		private function sendAcknowledgement():void
		{
			//Create XML
			var dataHeader:String = '<?xml version="1.0" encoding="UTF-8"?>';
			var node:XML = 
				<BroadsoftDocument protocol="CAP" version="14.0">
					<command commandType="acknowledgement">
						<commandData>
							<user userType="CallClient" userUid="" id="">
								<message messageName="registerResponse"/>
								<applicationId>{applicationId}</applicationId>
							</user>
						</commandData>
					</command>
				</BroadsoftDocument>;
			
			//Set userUid and id attribute
			var userNode:XML = node.descendants("user")[0];
			userNode.@userUid = _userUID;
			userNode.@id = _userId;
			
			//Build socket request
			var request:String = dataHeader +"\n" + node.toXMLString();
			//trace(request);
			
			//Send request to server
			sendRequest(request);
		}
		
		/**
		 * 
		 * 
		 * @public
		 */
		public function dial(number:String):void
		{
			//Create XML
			var dataHeader:String = '<?xml version="1.0" encoding="UTF-8"?>';
			var node:XML = 
				<BroadsoftDocument protocol="CAP" version="15.0">
					<command commandType="callAction">
						<commandData>
							<user userType="CallClient" id="">
								<action actionType="Dial">
									<actionParam actionParamName="Number">{formatPhoneNumber(number)}</actionParam>
								</action>
								<applicationId>{applicationId}</applicationId>
							</user>
						</commandData>
					</command>
				</BroadsoftDocument>;
			
			//set the id attribute of the user node
			var userNode:Object = node.descendants("user");
			userNode.@id = _userId;
			
			//Build socket request
			var request:String = dataHeader +"\n" + node.toXMLString();
			
			//Send request to server
			sendRequest(request);
		}
		
		/**
		 * 
		 * 
		 * @public
		 */
		public function release():void
		{
			//Create XML
			var dataHeader:String = '<?xml version="1.0" encoding="UTF-8"?>';
			var node:XML = 
				<BroadsoftDocument protocol="CAP" version="15.0">
					<command commandType="callAction">
						<commandData>
							<user userType="CallClient" id="">
								<action actionType="Release">
									<actionParam actionParamName="CallId">{_currentCallId}</actionParam>
								</action>
								<applicationId>{applicationId}</applicationId>
							</user>
						</commandData>
					</command>
				</BroadsoftDocument>;
			
			//set the id attribute of the user node
			var userNode:Object = node.descendants("user");
			userNode.@id = _userId;
			
			//Build socket request
			var request:String = dataHeader +"\n" + node.toXMLString();
			
			//Send request to server
			sendRequest(request);
		}
		
		/**
		 * 
		 * 
		 * @public
		 */
		public function parseMessage():void
		{
			
		}
		
		/**
		 * 
		 * 
		 * @public
		 */
		public function parseCommand(data:XML):void
		{
			//Parse Commands
			var nodes:XMLList = data.descendants("command");
			
			//Set Command Type
			var commandType:String = nodes[0].@commandType;
			
			//Command Action
			switch(commandType)
			{
				case "responseAuthentication":
					onResponseAuthentication(data);
					break;
				case "registerResponse":
					onRegisterResponse(data);
					break;
				case "sessionUpdate":
					break;
				case "profileUpdate":
					break;
				case "callUpdate":
					onCallUpdate(data);
					break;
				case "unRegister":
					onUnregister(data);
					break;
			}
		}
		
		private function formatPhoneNumber(number:String):String
		{
			number = StringUtil.remove(number, "(");
			number = StringUtil.remove(number, ")");
			number = StringUtil.remove(number, "-");
			number = StringUtil.remove(number, " ");
			trace("MOD PHONE NUM:", number);
			return number;
		}
		
		private function parseCallUpdate(data:XML):void
		{
			var commands:XMLList = data.descendants("command");
			var totalCommands:int = commands.length();
			
			//trace("Total Commands:", totalCommands,"All Commands:",ObjectUtil.toString(commands));
			
			if(totalCommands == 1)
			{
				//determine the state of the call update
				var commandState:int = commands.descendants("state");
				var call:XMLList = commands.descendants("call");
				
				//initialize event to dispatch
				var ev:CallUpdate;
				
				//command states:
				//idle
				if(commandState == 0)
				{
					trace("phone idle...");
					ev = new CallUpdate(CallUpdate.IDLE);
				}
				//alerting (dialing)
				else if(commandState == 1)
				{
					trace("call dialing (alerting)...");
					ev = new CallUpdate(CallUpdate.ALERTING);
				}
				//answered
				else if(commandState == 2)
				{
					trace("call answered (active)...");
					ev = new CallUpdate(CallUpdate.ACTIVE);
				}
				//held by user
				else if(commandState == 3)
				{
					trace("call put on hold by user...");
					ev = new CallUpdate(CallUpdate.HELD);
				}
				//held by callee
				else if(commandState == 4)
				{
					trace("put on hold by callee...");
					ev = new CallUpdate(CallUpdate.REMOTE_HELD);
				}
				//hung up
				else if(commandState == 5)
				{
					trace("call released...");
					ev = new CallUpdate(CallUpdate.RELEASED);
				}
				
				//set call Id
				_currentCallId = call.@callId;
				ev.callId = _currentCallId;
				
				//dispatch call update event
				dispatchEvent(ev);
			}
			else if(totalCommands > 1)
			{
				throw new Error("Multiple commands detected. No error handling available. Please notify an administrator of this issue.");
				
			}
				
		}
		
		//--------------------------------------------------------------------------
		//
		//  Event Handlers
		//
		//--------------------------------------------------------------------------
		/**
		 * Handler for the socket's CONNECT event.
		 *
		 * @param event CONNECT event
		 */
		private function connectHandler(event:Event):void
		{
			_rawResponse = ""; //clear response buffer for each new socket connection
			
			var requestLine:String = _resource + " HTTP/1.0\n";
			
			var now:Date = new Date();
			var headers:String = "Date: " + DAYS[now.day] + ", " + now.date + " " + MONTHS[now.month] + " " + now.fullYear +
				" " + now.hours + ":" + now.minutes + ":" + now.seconds + "\n";
			
			
			//Basic Authentication
			var isAuth:Boolean = (_username && _password) ? true : false;
			
			if(isAuth)
			{
				//encodes the username and password with Base64
				var encoder:Base64Encoder = new Base64Encoder();
				encoder.encode(_username + ":" + _password);
				
				//adds authorication to the request header
				headers += "Authorization: Basic " + encoder.toString() + "\n";
			}
			
			
			if (_contentType != null)
			{
				headers += "Content-Type: " + _contentType + "\n";
			}
			
			if (_body == null)
			{
				_body = "";
			}
			else
			{
				headers += "Content-Length: " + _body.length + "\n";
			}
			
			var request:String = requestLine + headers + "\n" + _body;
			
			if (_secure)
			{
				_secureSocket.writeUTFBytes(request);
				_secureSocket.flush();
			}
			else
			{
				_socket.writeUTFBytes(request);
				_socket.flush();
			}
			
			_body = null;
		}
		
		/**
		 * Handler for the socket's SOCKET_DATA event. Reads data from the socket into an instance variable.
		 *
		 * @param event SOCKET_DATA event
		 */
		private function dataHandler(event:ProgressEvent):void
		{
			var response:String;
			
			if (_secure)
			{
				while (_secureSocket.bytesAvailable)
				{
					_rawResponse += _secureSocket.readUTFBytes(_socket.bytesAvailable);
				}
			}
			else
			{
				while (_socket.bytesAvailable)
				{
					response  = _socket.readUTFBytes(_socket.bytesAvailable);
					
					//Prevents multi-message delivery, only reads the first event
					if(response.split('<?xml version="1.0" encoding="UTF-8"?>').length > 2)
					{
						response = response.split('<?xml version="1.0" encoding="UTF-8"?>')[1];
						response = '<?xml version="1.0" encoding="UTF-8"?>' + response;
					}
					
					//Dispatch xml response event
					var responseEvent:XMLResponse = new XMLResponse(XMLResponse.XML, true);
					responseEvent.body = response;
					//dispatchEvent(responseEvent);
					
					//Parse XML Command
					parseCommand(XML(response));
					
					/*
					trace("::SOCKET DATA::\n" + response);
					
					var commandType:String = XML(response).children()[0].@commandType;
					trace("CTYPE:",commandType);
					
					//Set nonce
					if(commandType == "responseAuthentication")
					{
					nonce = XML(response).descendants("nonce")[0];
					trace("-->NONCE SET:", nonce);
					}
					//Set userUid
					else if(commandType == "registerResponse")
					{
					_userUID = XML(response).children()[0].commandData.user.@userUid;
					trace("-->USERUID SET:", _userUID);
					}
					else if(commandType == "callUpdate")
					{
					_currentCallId = XML(response).children()[0].commandData.user.call.@callId;
					trace("-->CURRENT CALLID:", _currentCallId);
					}
					else
					{
					//trace("::SOCKET DATA::\n" + XML(response).toString());
					}
					
					_rawResponse += _socket.readUTFBytes(_socket.bytesAvailable);
					*/
				}
			}
		}
		
		/**
		 * Handler for the socket's CLOSE event. Reads the instance variable populated by the dataHandler() method.
		 *
		 * @param event CLOSE event
		 */
		private function closeHandler(event:Event):void
		{
			var lines:Array = _rawResponse.split("\n");
			
			var isFirstLine:Boolean = true;
			var isBody:Boolean = false;
			var statusCode:int;
			var statusMessage:String;
			var headers:Object = new Object();
			var body:String = "";
			
			for each (var line:String in lines)
			{
				if (isFirstLine)
				{
					var startStatusCode:int = line.indexOf(" ");
					var endStatusCode:int = line.indexOf(" ", startStatusCode+1);
					statusCode = parseInt(line.substr(startStatusCode, endStatusCode));
					statusMessage = StringUtil.trim(line.substr(endStatusCode+1));
					isFirstLine = false;
				}
				else if (StringUtil.trim(line) == "")
				{
					isBody = true; // blank line separates headers from body
				}
				else if (isBody)
				{
					body += line;
				}
				else // headers
				{
					var colonIndex:int = line.indexOf(":");
					var headerName:String = line.substr(0, colonIndex);
					var headerValue:String = line.substr(colonIndex+1);
					headers[headerName] = StringUtil.trim(headerValue);
				}
			}
			
			var httpEvent:HttpEvent = new HttpEvent(EVENT_RESULT, null, _resource);
			httpEvent.data = _rawResponse;
			httpEvent.response = new HttpResponse(statusCode, statusMessage, headers, body);
			dispatchEvent(httpEvent);
		}
		
		/**
		 * Handles security errors.
		 *
		 * @param event Security error event
		 */
		private function securityErrorHandler(event:SecurityErrorEvent):void
		{
			var httpEvent:HttpEvent = new HttpEvent(EVENT_FAULT, null, _resource);
			httpEvent.text = event.text;
			httpEvent.response = new HttpResponse(500, "Internal Server Error", null, null);
			
			dispatchEvent(httpEvent);
		}
		
		/**
		 * Handles IO errors.
		 *
		 * @param event IO error event
		 */
		private function ioErrorHandler(event:IOErrorEvent):void
		{
			var httpEvent:HttpEvent = new HttpEvent(EVENT_FAULT, null, _resource);
			httpEvent.text = event.text;
			httpEvent.response = new HttpResponse(500, "Internal Server Error", null, null);
			
			dispatchEvent(httpEvent);
		}
		
		/**
		 * @private
		 */
		private function onResponseAuthentication(data:XML):void
		{
			//Set nonce
			_nonce = data.descendants("nonce")[0];
			trace("nonce =", _nonce);
			
			if(_nonce)
			{
				//Register Response
				registerRequest();
			}
			else
			{
				var loginFailedEvent:BroadsoftServiceEvent = new BroadsoftServiceEvent(BroadsoftServiceEvent.LOGIN_FAILED);
				dispatchEvent(loginFailedEvent);
			}
			
		}
		
		/**
		 * @private
		 */
		private function onRegisterResponse(data:XML):void
		{
			//Set UserUID
			_userUID = data.children()[0].commandData.user.@userUid;
			trace("userUID =", _userUID);
			
			//Send Acknowledgement
			if(_userUID != null && _userUID != "")
			{
				sendAcknowledgement();
				
				//dispatch login complete event
				var loginSuccessEvent:BroadsoftServiceEvent = new BroadsoftServiceEvent(BroadsoftServiceEvent.LOGIN_SUCCESS);
				dispatchEvent(loginSuccessEvent);
			}
			else
			{
				var loginFailedEvent:BroadsoftServiceEvent = new BroadsoftServiceEvent(BroadsoftServiceEvent.LOGIN_FAILED);
				dispatchEvent(loginFailedEvent);
			}
		}
		
		/**
		 * @private
		 */
		private function onCallUpdate(data:XML):void
		{
			//parse the results of a call update command
			parseCallUpdate(data);
		}
		
		/**
		 * onUnregister description.
		 *
		 * @private
		 */
		private function onUnregister(data:XML):void 
		{
			var ev:CallError = new CallError(CallError.UNREGISTER);
			dispatchEvent(ev);
		}
		
		//--------------------------------------------------------------------------
		//
		//  Properties
		//
		//--------------------------------------------------------------------------
		/**
		 * Gets the address of the web service provider.
		 *
		 * @return Web service provider
		 */
		public function get server():String
		{
			return _server;
		}
		
		/**
		 * Sets the address of the web service provider.
		 *
		 * @param server Web service provider
		 */
		public function set server(server:String):void
		{
			_server = server;
		}
		
		/**
		 * Gets the port on which the web service provider is listening.
		 *
		 * @return Port on web service provider
		 */
		public function get port():int
		{
			return _port;
		}
		
		/**
		 * Sets the port on which the web service provider is listening.
		 *
		 * @param port Port on web service provider
		 */
		public function set port(port:int):void
		{
			_port = port;
		}
		
		/**
		 * Gets the port on which the server is listening for policy file requests.
		 *
		 * @return Port on which the server is listening for policy file requests
		 */
		public function get policyFilePort():int
		{
			return _policyFilePort;
		}
		
		/**
		 * Sets the port on which the server is listening for policy file requests.
		 *
		 * @param policyFilePort Port on which the server is listening for policy file requests
		 */
		public function set policyFilePort(policyFilePort:int):void
		{
			_policyFilePort = policyFilePort;
		}
		
		/**
		 * Gets the value indicating if a new socket should be created for each request. It has been observed that when
		 * making multiple calls from the same event using the same socket, the socket does not connect after the first
		 * call. Though not as efficient, creating a new socket each time resolves the problem.
		 *
		 * @return New socket indicator
		 */
		public function get newSocketEachRequest():Boolean
		{
			return _newSocketEachRequest;
		}
		
		/**
		 * Sets the value indicating if a new socket should be created for each request. It has been observed that when
		 * making multiple calls from the same event using the same socket, the socket does not connect after the first
		 * call. Though not as efficient, creating a new socket each time resolves the problem.
		 *
		 * @param newSocketEachRequest New socket indicator
		 */
		public function set newSocketEachRequest(newSocketEachRequest:Boolean):void
		{
			_newSocketEachRequest = newSocketEachRequest;
		}
		
		/**
		 * Gets the path to the resource (minus the server and port information).
		 *
		 * @return Path to resource
		 */
		public function get resource():String
		{
			return _resource;
		}
		
		/**
		 * Sets the path to the resource (minus the server and port information).
		 *
		 * @param resource Path to resource
		 */
		public function set resource(resource:String):void
		{
			_resource = resource;
		}
		
		/**
		 * Gets the content type of the request body.
		 *
		 * @return Content type of the request
		 */
		public function get contentType():String
		{
			return _contentType;
		}
		
		/**
		 * Sets the content type of the request body.
		 *
		 * @param contentType Content type of the request
		 */
		public function set contentType(contentType:String):void
		{
			_contentType = contentType;
		}
		
		/**
		 * Indicates whether or not a secure SSL connection should be used.
		 *
		 * @return Secure connection indicator
		 */
		public function get secure():Boolean
		{
			return _secure;
		}
		
		/**
		 * Sets whether or not a secure SSL connection should be used.
		 *
		 * @param secure Secure connection indicator
		 */
		public function set secure(secure:Boolean):void
		{
			_secure = secure;
		}
		
		/**
		 * Gets the authentication username.
		 * 
		 * @return Auth Username
		 */
		public function get username():String
		{
			return _username;
		}
		
		/**
		 * Sets the username for authentication
		 * 
		 * @params username Username used to authenticate.
		 */
		public function set username(value:String):void
		{
			_username = value;
		}
		
		/**
		 * Gets the authentication password.
		 * 
		 * @return Auth Password
		 */
		public function get password():String
		{
			return _password;
		}
		
		/**
		 * Sets the authentication password.
		 * 
		 * @params password Password used to authenticate.
		 */
		public function set password(value:String):void
		{
			_password = value;
		}
		
		/**
		 * The unique name of the application.
		 */
		public function get applicationId():String
		{
			if(_applicationId == null)
				return "TierSevenBroadsoftExample";
			else
				return _applicationId;
		}
		
		public function set applicationId(value:String):void
		{
			_applicationId = value;
		}
		
		public function get userId():String
		{
			return _userId;
		}
		
		public function set userId(value:String):void
		{
			_userId = value;
		}
		
		public function get nonce():String
		{
			return _nonce;
		}
		
		public function set nonce(value:String):void
		{
			_nonce = value;
		}
		
		public function get userUID():String
		{
			return _userUID;
		}
		
		public function set userUID(value:String):void
		{
			_userUID = value;
		}
	}
}