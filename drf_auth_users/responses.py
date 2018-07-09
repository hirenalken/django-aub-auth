#!/usr/bin/env python
# -*- coding: utf-8 -*-


def generate_response(
        success: object,
        msg: object,
        payload: object = {},
        err_code: object = None) -> object:
    """
        Generates json response
    """
    response_json = {'success': success, 'message': msg, 'payload': payload}

    if not success:
        if err_code:
            response_json['error_code'] = err_code

    return response_json


def generate_success_response(response_message: dict, payload={}):
    """
        Generates response for successful operations
    """
    return generate_response(
        success=True,
        msg=response_message['message'],
        payload=payload)


def generate_failure_response(error_message: dict, payload={}):
    """
        Generate response in case of error
    """
    return generate_response(success=False,
                             msg=error_message['message'],
                             payload=payload,
                             err_code=error_message['err_code'])