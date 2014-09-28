# Author: Zhang Huangbin <zhb _at_ iredmail.org>
# Purpose: Check per-recipient message size limit stored in Amavisd database
#          (column `policy.message_size_limit`), used in Amavisd setting
#          '@lookup_sql_dsn'.
#
# How to use this plugin:
#
# *) Set Amavisd lookup SQL database related parameters (amavisd_db_*) in
#    iRedAPD config file `settings.py`, and enable this plugin.
#
# *) Enable iRedAPD in Postfix `smtpd_end_of_data_restrictions`.
#    For example:
#
#    smtpd_end_of_data_restrictions =
#           check_policy_service inet:[127.0.0.1]:7777,
#           ...
#
# *) Restart both iRedAPD and Postfix services.

import logging
from libs import SMTP_ACTIONS
from libs.amavisd import core as amavisd_lib

SMTP_PROTOCOL_STATE = 'END-OF-MESSAGE'

# Connect to amavisd database
REQUIRE_AMAVISD_DB = True


def restriction(**kwargs):
    adb_cursor = kwargs['amavisd_db_cursor']

    if not adb_cursor:
        logging.debug('Error, no valid Amavisd database connection.')
        return SMTP_ACTIONS['default']

    recipient = kwargs['recipient']

    # message size in bytes
    msg_size = int(kwargs['smtp_session_data']['size'])
    logging.debug('Message size: %d' % msg_size)

    wanted_policy_columns = ['policy_name', 'message_size_limit']

    (status, policy_records) = amavisd_lib.get_applicable_policy(adb_cursor,
                                                                 recipient,
                                                                 policy_columns=wanted_policy_columns,
                                                                 **kwargs)
    if not status:
        return SMTP_ACTIONS['default']

    if not policy_records:
        logging.debug('No policy found.')
        return SMTP_ACTIONS['default']

    for rcd in policy_records:
        (policy_name, message_size_limit) = rcd
        if not message_size_limit:
            logging.debug('SKIP: policy_name %s, no valid message_size_limit: %s' % (
                policy_name,
                str(message_size_limit))
            )
            continue
        else:
            message_size_limit = int(message_size_limit)
            if message_size_limit > msg_size:
                logging.debug('SKIP, limit not reached. policy_name %s has valid message_size_limit: %s' % (
                    policy_name,
                    str(message_size_limit))
                )
            else:
                logging.debug('Reject by policy_name %s, message_size_limit: %s' % (
                    policy_name,
                    str(message_size_limit))
                )
                return SMTP_ACTIONS['reject_message_size_exceeded']

    return SMTP_ACTIONS['default']