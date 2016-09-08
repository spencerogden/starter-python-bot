import json
import logging
import re

from wit import Wit

logger = logging.getLogger(__name__)

class RtmEventHandler(object):
    def __init__(self, slack_clients):
        self.clients = slack_clients
        
        self.wit_token = "L54MRSYYCC7KUS7OWBT3PVTGJTS462T5"
        logging.info("wit token: {}".format(self.wit_token))
        self.wit_client = Wit(self.wit_token)
        logging.info("wit: {}".format(dir(self.wit_client)))

    def handle(self, event):
        if 'type' in event:
            self._handle_by_type(event['type'], event)

    def _handle_by_type(self, event_type, event):
        # See https://api.slack.com/rtm for a full list of events
        if event_type == 'error':
            # error
            logger.debug('Error event')
        elif event_type == 'message':
            # message was sent to channel
            self._handle_message(event)
        elif event_type == 'channel_joined':
            # you joined a channel
            logger.debug('Channel joined')
        elif event_type == 'group_joined':
            # you joined a private group
            logger.debug('Group joined')
        else:
            pass

    def _handle_message(self, event):
        # Filter out messages from the bot itself
        if not self.clients.is_message_from_me(event['user']):

            msg_txt = event['text']

            if self.clients.is_bot_mention(msg_txt):
                # User mentiones bot
                session_id = 'test'
                channel_id = event['channel']
                context = {
                    'channel_id':channel_id,
                    'user': event['user'],
                    }
                logger.debug('Sending msg: {} to Wit.ai'.format(msg_txt))    
                resp = self.wit_client.converse(session_id, msg_txt,context)
                logger.debug('Got resp: {}'.format(resp))
                if resp['type'] == 'msg':
                    if isinstance(channel_id, dict):
                        channel_id = channel_id['id']
                    logger.debug('Sending msg: {} to channel: {}'.format(msg, channel_id))
                    channel = self.clients.rtm.server.channels.find(channel_id)
                    channel.send_message("{}".format(msg.encode('ascii', 'ignore')))
                elif resp['type'] == 'action':
                    logger.debug('do {}'.format(resp['action']))
