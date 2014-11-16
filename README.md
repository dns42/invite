# Invite

Really simple SIP REGISTER/INVITE utility, using sofia-sip.

Does not support audio and video, in fact it does not even expect to
complete a session. All this does is make a phone ring for up to a
configurable number of seconds.

Typically useful to signal events on a private branch extension. The
doorbell button on my front door calls this.

## Example

./invite
	--user 610 --pass *** --realm fritz.box
	--server harv 'sip:**611@fritz.box'
