# coding=utf-8


def jwt_response_payload_handler(token, user=None, request=None):
    if user.verify == 2:
        return {
            "status": 1,
            "token": token,
            "message": "superUser",
            "prefix": user.id,
            "role": user.verify
        }
    elif user.verify == 1:
        return {
            "status": 1,
            "token": token,
            "message": "originalUser",
            "prefix": user.id,
            "role": user.verify
        }
    else:
        return {
            "status": 0,
            "message": "未通过审核"
        }
