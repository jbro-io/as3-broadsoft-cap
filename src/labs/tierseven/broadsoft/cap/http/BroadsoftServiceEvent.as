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
	public class BroadsoftServiceEvent extends Event
	{
		//--------------------------------------------------------------------------
		//
		//  Variables
		//
		//--------------------------------------------------------------------------
		public static const LOGIN_SUCCESS:String = "broadsoftLoginSuccess";
		public static const LOGIN_FAILED:String = "broadsoftLoginFailed";
		
		//--------------------------------------------------------------------------
		//
		//  Constructor
		//
		//--------------------------------------------------------------------------
		/**
		 * Constructor.
		 */
		public function BroadsoftServiceEvent(type:String, bubbles:Boolean=false, cancelable:Boolean=false)
		{
			super(type, bubbles, cancelable);
		}
		
		//--------------------------------------------------------------------------
		//
		//  Methods
		//
		//--------------------------------------------------------------------------
		override public function clone():Event
		{
			return new BroadsoftServiceEvent(type, bubbles, cancelable);
		}
		
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