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
    elif user.verify == 0:
        return {
            "status": 2,
            "message": " 用户在审核中，登录认证失败"
        }
    else:
        return {
            "status": 0,
            "message": " 用户审核被拒，登录认证失败"
        }