package labs.tierseven.broadsoft.cap.http
{
	//--------------------------------------------------------------------------
	//
	//  Imports
	//
	//--------------------------------------------------------------------------
	import flash.events.Event;
	
	
	/**
	 * Description of this class.
	 *
	 * @author Jonathan Broquist
	 * @modified Mar 9, 2010
	 */
	public class CallUpdate extends Event
	{
		//--------------------------------------------------------------------------
		//
		//  Variables
		//
		//--------------------------------------------------------------------------
		public static const IDLE:String = "callIdle";
		public static const ALERTING:String = "callAlerting";
		public static const ACTIVE:String = "callActive";
		public static const HELD:String = "callHeldByCaller";
		public static const REMOTE_HELD:String = "callHeldByCallee";
		public static const RELEASED:String = "callReleased";
		public static const DETACHED:String = "callDetached";
		public static const CLIENT_ALERTING:String = "callClientAlerting";
		
		public var callId:String;
		
		//--------------------------------------------------------------------------
		//
		//  Constructor
		//
		//--------------------------------------------------------------------------
		/**
		 * Constructor.
		 */
		public function CallUpdate(type:String, bubbles:Boolean=false, cancelable:Boolean=false)
		{
			super(type, bubbles, cancelable);
		}
		
		//--------------------------------------------------------------------------
		//
		//  Methods
		//
		//--------------------------------------------------------------------------
		
		//--------------------------------------------------------------------------
		//
		//  Event Handlers
		//
		//--------------------------------------------------------------------------
		
		//--------------------------------------------------------------------------
		//
		//  Properties
		//
		//--------------------------------------------------------------------------
	}
}