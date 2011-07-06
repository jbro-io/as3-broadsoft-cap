package labs.tierseven.broadsoft.cap.http
{
	import flash.events.Event;
	
	public class XMLResponse extends Event
	{
		public static const XML:String = "xmlResponse";
		public static const RESPONSE_AUTHENTICATION:String = "responseAuthentication";
		public static const REGISTER_RESPONSE:String = "registerResponse";
		public static const CALL_UPDATE:String = "callUpdate";
		
		public var body:Object;
		
		public function XMLResponse(type:String=XML, bubbles:Boolean=false, cancelable:Boolean=false)
		{
			super(type, bubbles, cancelable);
		}
	}
}