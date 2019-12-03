# coding=utf-8
import datetime
import os
import pandas as pd
import re
import ujson
import jwt
import xlrd
from dateutil.relativedelta import relativedelta
from django.contrib.auth.hashers import check_password
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponse, FileResponse
import django.utils.timezone
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from models import *
from handleVueProject.pubprivkeyauth import createh, delete
from handleVueProject.pubprivkeyauth import reslove
from handleVueProject import serverquery
from serverquery import config

UserModel = get_user_model()


def auth_permission_required(perm):
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            # 格式化权限
            perms = (perm,) if isinstance(perm, str) else perm

            if request.user.is_authenticated:
                # 正常登录用户判断是否有权限
                if not request.user.has_perms(perms):
                    raise PermissionDenied
            else:
                try:
                    auth = request.META.get('HTTP_AUTHORIZATION').split()
                except AttributeError:
                    return JsonResponse({"status": 401, "message": "No authenticate header"})
                # 用户通过 API 获取数据验证流程
                # if auth[0].lower() == 'token':
                try:
                    dict = jwt.decode(auth[0], settings.SECRET_KEY, algorithms=['HS256'])
                    username = dict.get('username')
                except jwt.ExpiredSignatureError:
                    return JsonResponse({"status": 401, "message": "Token expired"})
                except jwt.InvalidTokenError:
                    return JsonResponse({"status": 401, "message": "Invalid token"})
                except Exception as e:
                    return JsonResponse({"status": 401, "message": "Can not get user object"})
                try:
                    user = UserModel.objects.get(username=username)
                except UserModel.DoesNotExist:
                    return JsonResponse({"status": 401, "message": "User Does not exist"})
                if not user.is_active:
                    return JsonResponse({"status": 401, "message": "User inactive or deleted"})
                    # # Token 登录的用户判断是否有权限
                    # if not user.has_perms(perms):
                    #     return JsonResponse({"status_code": 403, "message": "PermissionDenied"})
                # else:
                #     return JsonResponse({"status": 401, "message": "Not support auth type"})
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator


def register(request):
    userName = request.POST["userName"]
    companyName = request.POST["companyName"]
    password = request.POST['userPassword']
    userPhone = request.POST['userPhone']
    userEmail = request.POST['userEmail']
    userCardId = request.POST['userCardId']
    user1 = user.objects.filter(username=userName)
    user2 = user.objects.filter(company=companyName)
    now = django.utils.timezone.datetime.now().strftime('%Y-%m-%d')
    if password != "" and userName != "" and userEmail != "" and userCardId != "" and userPhone != "" and companyName != "":
        if user1.exists():
            resp = {'status': 0, 'message': '该用户名已存在'}
            return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')
        elif user2.exists():
            resp = {'status': 0, 'message': '该公司已存在'}
            return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')
        else:
            accessory = request.FILES.get("file")
            if accessory != None:
                destination = open("upload/" + accessory.name, 'wb')
                for chunk in accessory.chunks():  # 分块写入文件
                    destination.write(chunk)
                destination.close()
                after = os.path.splitext(accessory.name)[1]
                os.rename("upload/" + accessory.name, "upload/" + userName + after)
                user1 = user.create(userName, password, userPhone, userEmail, userCardId, userName, 0, now,
                                    companyName)
                user1.set_password(password)
                user1.save()
                resp = {'status': 1, 'message': '注册成功，审核通过后即可登录'}
                return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')
            else:
                resp = {'status': 0, 'message': '请上传审核文件'}
                return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')
    else:
        resp = {'status': 0, 'message': '参数不能为空'}
        return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def userSelect(request):
    data = ujson.loads(request.body.decode('utf-8'))
    userName = ""
    companyName = ""
    startTime = "1979-09-09"
    endTime = "2999-09-09"
    if data.get('userName'):
        userName = data.get('userName')
    if data.get('companyName'):
        companyName = data.get('companyName')
    if data.get('startTime'):
        startTime = data.get('startTime')
    if data.get('endTime'):
        endTime = data.get('endTime')
    page = data.get('pageNum')
    pageSize = data.get('pageSize')
    user1 = user.objects.filter(verify=1, username__contains=userName, company__contains=companyName, time__lte=endTime,
                                time__gte=startTime).values('id', 'username', 'phonenumber', 'email', 'card', 'company',
                                                            'time')
    paginator1 = Paginator(user1, pageSize)  # 每页显示4条
    if page:
        data_list = paginator1.page(page).object_list
    else:
        data_list = paginator1.page(1).object_list
    resp = {'data': data_list, 'totalCount': paginator1.count}
    return HttpResponse(ujson.dumps(resp, ensure_ascii=False), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def userDelete(request):
    data = ujson.loads(request.body.decode('utf-8'))
    id = data.get('id')
    user1 = user.objects.get(id=id)
    username = user1.username
    user1.delete()
    os.remove("upload/" + username + '.xlsx')
    resp = {'status': 1, 'message': 'delete success'}
    return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def userUpdate(request):
    data = ujson.loads(request.body.decode('utf-8'))
    id = data.get('id')
    userPhone = data.get('userPhone')
    userEmail = data.get('userEmail')
    userCard = data.get('userCardId')
    user.objects.filter(id=id).update(email=userEmail, phonenumber=userPhone, card=userCard)
    resp = {'status': 1, 'message': 'update success'}
    return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def userVerify(request):
    data = ujson.loads(request.body.decode('utf-8'))
    userName = ""
    companyName = ""
    startTime = "1979-09-09"
    endTime = "2999-09-09"
    if data.get('userName'):
        userName = data.get('userName')
    if data.get('companyName'):
        companyName = data.get('companyName')
    if data.get('startTime'):
        startTime = data.get('startTime')
    if data.get('endTime'):
        endTime = data.get('endTime')
    page = data.get('pageNum')
    pageSize = data.get('pageSize')
    user1 = user.objects.filter(verify__in=[0, 3], username__contains=userName, company__contains=companyName,
                                time__lte=endTime, time__gte=startTime).values('id', 'username', 'phonenumber', 'email',
                                                                               'card', 'company',
                                                                               'verify', 'time')
    paginator1 = Paginator(user1, pageSize)  # 每页显示4条
    if page:
        data_list = paginator1.page(page).object_list
    else:
        data_list = paginator1.page(1).object_list
    resp = {'data': data_list, 'totalCount': paginator1.count}
    return HttpResponse(ujson.dumps(resp, ensure_ascii=False), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def userRefuse(request):
    data = ujson.loads(request.body.decode('utf-8'))
    id = data.get('id')
    user.objects.filter(id=id).update(verify=3)
    resp = {'status': 1, 'message': 'success'}
    return HttpResponse(ujson.dumps(resp, ensure_ascii=False), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def userAccept(request):
    data = ujson.loads(request.body.decode('utf-8'))
    id = data.get('id')
    user.objects.filter(id=id).update(verify=1)
    resp = {'status': 0, 'message': 'success'}
    return HttpResponse(ujson.dumps(resp, ensure_ascii=False), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def alterPassword(request):
    data = ujson.loads(request.body.decode('utf-8'))
    id = data.get('id')
    oldPassword = data.get('oldPassword')
    newPassword = data.get('newPassword')
    user1 = user.objects.get(id=id)
    oldPassword1 = user1.password
    if check_password(oldPassword, oldPassword1):
        user1.set_password(newPassword)
        user1.save()
        resp = {'status': 1, 'message': 'success'}
        return HttpResponse(ujson.dumps(resp, ensure_ascii=False), content_type='application/json; charset=utf-8')
    else:
        resp = {'status': 0, 'message': '密码错误'}
        return HttpResponse(ujson.dumps(resp, ensure_ascii=False), content_type='application/json; charset=utf-8')


@auth_permission_required('handleProjectVue.user')
def downVerify(request):
    data = ujson.loads(request.body.decode('utf-8'))
    id = data.get('id')
    # id = request.GET['id']
    user1 = user.objects.get(id=id)
    file = open("upload/" + user1.username + '.xlsx', 'rb')
    HttpResponse = FileResponse(file)
    HttpResponse['Content-Type'] = 'application/octet-stream'
    HttpResponse['Content-Disposition'] = 'attachment;filename="example.xlsx"'
    return HttpResponse


@auth_permission_required('handleProjectVue.user')
def downVerify1(request):
    file = open("mobanUpload/" + 'example.xlsx', 'rb')
    HttpResponse = FileResponse(file)
    HttpResponse['Content-Type'] = 'application/octet-stream'
    HttpResponse['Content-Disposition'] = 'attachment;filename="example.xlsx"'
    return HttpResponse


@auth_permission_required('handleProjectVue.user')
def ServerList(request):
    serverlist = server.objects.values('id', 'ip', 'port', 'prefix')
    resp = {'status': 1, 'message': serverlist}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')
def CreateHandle(request):
    response = ujson.loads(request.body.decode('utf-8'))
    data = response.get('Data')
    record.index = []
    record.type = []
    record.value = []
    for i in data:
        record.index.append(i.get('index'))
        record.type.append(i.get('type'))
        record.value.append(i.get('data'))
    perfix = response.get('prefix')
    handle_record = reslove(perfix, ip='172.171.1.80', port=8080)
    if handle_record is not None:
        resp = {'status': 0, 'message': '该前缀已经存在'}
        return HttpResponse(ujson.dumps(resp))
    now = django.utils.timezone.datetime.now().strftime('%Y-%m-%d')
    userid = response.get('userid')
    user1 = user.objects.get(id=userid)
    username = user1.username
    company = user1.company
    serverid = response.get('serverid')
    server2 = server.objects.get(id=serverid)
    handle1 = handles.create(company=company, username=username, perix=perfix, count=0, time=now, server=server2)
    handle1.save()
    createh(record, perfix, server2.ip, server2.port)
    resp = {'status': 1, 'message': '创建成功'}
    return HttpResponse(ujson.dumps(resp), content_type='application/json; charset=utf-8')


def analyze_json(jsons):
    handle.context = []
    if isinstance(jsons, dict):
        for key in jsons.keys():
            if key == 'handle':
                handle.perix = jsons.get(key)
            key_value = jsons.get(key)
            if isinstance(key_value, list):
                for json_array in key_value:  # dict1[str(key)] = str(key_value)
                    if isinstance(json_array, dict):
                        dict1 = {}
                        for json_key in json_array:
                            data = json_array.get(json_key)
                            if isinstance(data, dict):
                                for datakey in data:
                                    if datakey == 'value':
                                        dict1['datas'] = data.get(datakey)
                            else:
                                dict1[str(json_key)] = json_array.get(json_key)
                        # dict1[str(key)] = str(key_value)
                    handle.context.append(dict1)
    return handle


@auth_permission_required('handleProjectVue.user')
def Classifiedquery(request):
    if request.method != 'POST':
        resp = {'status': 0, 'message': '请用post方法'}
        return HttpResponse(ujson.dumps(resp))
    data = ujson.loads(request.body.decode('utf-8'))
    biaoshi = data.get('prefix')
    type = data.get('type')
    handlepattern = '20.500.'
    niotpantter = 'cn.pub.xty.100'
    ecodepantter = '100036930100'
    oidpanntter = '1.2.156.86'
    DNSpattern = '[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?'
    now = django.utils.timezone.datetime.now().strftime('%Y-%m-%d')
    if type == 1 and re.search(handlepattern, biaoshi) != None:
        handleperix = biaoshi
        obj1 = handles.objects.filter(perix=handleperix)
        if obj1.exists():
            obj = handles.objects.get(perix=handleperix)
            obj.count += 1
            obj.save()
            handle_record = reslove(handleperix, obj.server.ip, obj.server.port)
        else:
            handle_record = reslove(handleperix, ip='172.171.1.80', port=8080)
        handle1 = analyze_json(handle_record)
        d1 = dict()
        d1['status'] = 1
        d1['type'] = 'handle'
        data = list()
        i = 0
        for row in handle1.context:
            i = i + 1
            data.append(row)
        # data.append(d1)
        if data == []:
            resp = {'status': 0, 'message': "标识不存在"}
            resolveRecord1 = resolveRecord.create(ip='172.171.1.80', prefix=handleperix, success=0, time=now)
            resolveRecord1.save()
            return HttpResponse(ujson.dumps(resp))
        else:
            d1['data'] = data
            if obj1.exists():
                obj = handles.objects.get(perix=handleperix)
                resolveRecord1 = resolveRecord.create(ip=obj.server.ip, prefix=handleperix, success=1, time=now)
                resolveRecord1.save()
            else:
                resolveRecord1 = resolveRecord.create(ip='172.171.1.80', prefix=handleperix, success=1, time=now)
                resolveRecord1.save()
            return HttpResponse(ujson.dumps(d1))
    if type == 2:
        list1 = []
        list2 = []
        count = handles.objects.filter(perix__startswith=biaoshi).count()
        handlelist = list(handles.objects.filter(perix__startswith=biaoshi))
        result = []
        if len(handlelist) != 0:
            for i in range(0, count):
                handle = handlelist[i]
                perix = handle.perix
                obj = handles.objects.get(perix=perix)
                handle_record = reslove(perix, obj.server.ip, obj.server.port)
                handle1 = analyze_json(handle_record)
                handle.count = handle.count + 1
                handle.save()
                d1 = dict()
                data = list()
                for row in handle1.context:
                    row['prefx'] = perix
                    data.append(row)
                    print row
                d1['data'] = data
                print  d1
                result.append(d1)
            reback = {}
            reback['status'] = 1
            reback['type'] = 'handle'
            reback['result'] = result
            return HttpResponse(ujson.dumps(reback))
        if len(handlelist) > 5000:
            resp = {'status': 0, 'message': "匹配标识过多"}
            return HttpResponse(ujson.dumps(resp))
    if (re.search(niotpantter, biaoshi) != None):
        datalist = serverquery.Naptrquery('172.171.1.80', biaoshi)
        if datalist == {}:
            resp = {'status': 0, 'message': "不能解析该标识"}
            return HttpResponse(ujson.dumps(resp))
        result = dict()
        result['type'] = 'niot'
        result['status'] = 1
        result['data'] = [datalist]
        return HttpResponse(ujson.dumps(result))
    if (re.search(ecodepantter, biaoshi) != None):
        datalist = serverquery.Naptrquery('172.171.1.80', biaoshi)
        if datalist == {}:
            resp = {'status': 0, 'message': "不能解析该标识"}
            return HttpResponse(ujson.dumps(resp))
        result = dict()
        result['type'] = 'ecode'
        result['status'] = 1
        result['data'] = [datalist]
        return HttpResponse(ujson.dumps(result))
    if (re.search(oidpanntter, biaoshi) != None):
        datalist = serverquery.Naptrquery('172.171.1.80', biaoshi)
        if datalist == {}:
            resp = {'status': 0, 'message': "不能解析该标识"}
            return HttpResponse(ujson.dumps(resp))
        result = dict()
        result['type'] = 'oid'
        result['status'] = 1
        result['data'] = [datalist]
        return HttpResponse(ujson.dumps(result))
    if re.search(DNSpattern, biaoshi) != None:
        datalist = serverquery.DNSquery('172.171.1.80', biaoshi)
        if datalist == []:
            resp = {'status': 0, 'message': "不能解析该标识"}
            return HttpResponse(ujson.dumps(resp))
        result = dict()
        result['status'] = 1
        result['type'] = 'dns'
        result['data'] = datalist
        return HttpResponse(ujson.dumps(result))
    resp = {'status': 0, 'message': "不能解析该标识"}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')
def Download(request):
    filename = "mobanexcel.xlsx"
    file = open("uploadexcel/" + filename, 'rb')
    response = FileResponse(file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="example.xlsx"'
    return response


@auth_permission_required('handleProjectVue.user')
def upload_file(request):
    if request.method == 'POST':
        userid = request.POST['userid']
        user1 = user.objects.get(id=userid)
        username = user1.username
        company = user1.company
        serverid = request.POST['serverid']
        server2 = server.objects.get(id=serverid)
        # username = request.POST['name']
        # company = request.POST['company']
        fix2 = request.POST['prefix']
        now = django.utils.timezone.datetime.now().strftime('%Y-%m-%d')
        uploadedFile = request.FILES.get('file', None)
        wb = xlrd.open_workbook(filename=uploadedFile.name, file_contents=request.FILES['file'].read())
        current_date = datetime.now()
        current_date_format = unicode(current_date.strftime('%Y-%m-%d %H-%M-%S'))
        destination = open(
            os.path.join("uploadexcel/" + current_date_format + "_" + username + "_" + uploadedFile.name),
            'wb+')  # 打开特定的文件进行二进制的写操作
        for chunk in uploadedFile.chunks():  # 分块写入文件
            destination.write(chunk)
        destination.close()
        succeedcreate = pd.DataFrame()
        error = pd.DataFrame()
        df = pd.read_excel(wb)
        if {'prefix', 'index', 'type', 'data'} <= set(list(df)):
            select_df = df[['prefix', 'index', 'type', 'data']]
            df2 = select_df.sort_values(by="prefix")
            # 存在空白单元格处理
            havenul = df2[df2.isnull().T.any()]
            havenul['error'] = ('have  null')
            error = havenul
            nonan_df = df2.dropna(axis=0, how='any')
            # index为100
            index100 = nonan_df[nonan_df['index'].isin([100])]
            index100['error'] = 'index 100 invalid'
            error = error.append(index100)
            no_index100 = nonan_df[~nonan_df['index'].isin([100])]

            # 处理数据相同行
            same_df = no_index100[no_index100.duplicated()]
            same_df['error'] = ('have same vlue , system have creat once succeed you don not neet to creat again')
            error = error.append(same_df)
            nosame_df = no_index100.drop_duplicates()
            group1 = nosame_df.groupby(nosame_df['prefix'])
            # 创建一个空的Dataframe
            errorprefix = pd.DataFrame()
            for a, b in group1:
                perfix = fix2 + str(a)
                perfix_record = handles.objects.filter(perix=perfix)
                if perfix_record.exists():
                    b['error'] = "perfix  have existsed"
                    errorprefix = errorprefix.append(b)
                else:
                    sameindex = b[b.duplicated(subset=['index'], keep=False)]
                    if sameindex.empty == False:
                        sameindex['error'] = ('have sanme index')
                        error = error.append(sameindex)
                        b.drop_duplicates(subset=['index'], keep=False, inplace=True)
                    if b.empty == False:
                        btype = b.astype('unicode')
                        correct = btype[btype['index'].str.match('^[1-9]\d*$') == True]
                        print correct
                        if correct.empty == False:
                            record.index = correct['index'].values.tolist()
                            record.type = correct['type'].values.tolist()
                            record.value = correct['data'].values.tolist()
                            handle1 = handles.create(company=company, username=username, perix=perfix, count=0,
                                                     time=now, server=server2)
                            handle1.save()
                            createh(record, perfix,server2.ip,server2.port)
                            succeedcreate = succeedcreate.append(correct)
                        if correct.shape[0] != b.shape[0]:
                            errortype = b[b['index'].str.match('^[1-9]\d*$') == False]
                            errortype['error'] = 'error index type'
                            error = error.append(errortype)
            error = error.append(errorprefix)
        else:
            error[u'没有获得正确的列名'] = ''
    filename = "result.xlsx"
    writer = pd.ExcelWriter("uploadexcel/" + username + "_" + filename)
    error.to_excel(writer, sheet_name='ERROR')
    succeedcreate.to_excel(writer, sheet_name='SUCCESS')
    writer.save()
    file = open("uploadexcel/" + username + "_" + filename, 'rb')
    response = FileResponse(file)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment; filename=result.xlsx'
    return response


@auth_permission_required('handleProjectVue.user')
def OneQuery(request):
    data = ujson.loads(request.body.decode('utf-8'))
    perix = data.get('prefix')
    handle1 = handles.objects.get(perix=perix)
    handle_record = reslove(perix, handle1.server.ip, handle1.server.port)
    handle1 = None
    handle1 = analyze_json(handle_record)
    for i in range(len(handle1.context)):
        handle1.context[i].pop('timestamp')
    if handle_record is not None:
        d1 = dict()
        d1['status'] = 1
        data = list()
        i = 0
        for row in handle1.context:
              if row.get('index') is not 100:
                i = i + 1
                data.append(row)
        if data == []:
            resp = {'status': 0, 'message': "标识不存在"}
            return HttpResponse(ujson.dumps(resp))
        d1['data'] = data
        return HttpResponse(ujson.dumps(d1))


@auth_permission_required('handleProjectVue.user')  # 查询
def ManyQuery(request):
    data = ujson.loads(request.body.decode('utf-8'))
    page = data.get('pageNum')  # 必须
    pageSize = data.get('pageSize')  # 必须_
    userid = data.get('userid')  # 必须
    user1 = user.objects.get(id=userid)
    companyname = ""
    startTime = "1979-09-09"
    endTime = "2999-09-09"
    creatname = ""
    prefix = ""
    if data.get('companyName'):
        companyname = data.get('companyname')
    if data.get('prefix'):
        prefix = data.get('prefix')
    if data.get('creatname'):
        creatname = data.get('creatname')
    if data.get('startTime'):
        startTime = data.get('startTime')
    if data.get('endTime'):
        endTime = data.get('endTime')
    if user1.verify == 2:
        handles1 = handles.objects.filter(username__contains=creatname, perix__contains=prefix,
                                          company__contains=companyname,
                                          time__lte=endTime, time__gte=startTime).values('id', 'username', 'perix',
                                                                                         'time', 'company', 'server_id')
        paginator = Paginator(handles1, pageSize)
        if page:
            data_list = paginator.page(page).object_list
        else:
            data_list = paginator.page(1).object_list

        resp = {'data': data_list, 'totalCount': paginator.count}
        return HttpResponse(ujson.dumps(resp))
    if user1.verify == 1:
        handles1 = handles.objects.filter(username=user1.username, perix__contains=prefix,
                                          company__contains=companyname,
                                          time__lte=endTime, time__gte=startTime).values('id', 'username', 'perix',
                                                                                         'time', 'company', 'server_id')
        paginator = Paginator(handles1, pageSize)
        if page:
            data_list = paginator.page(page).object_list
        else:
            data_list = paginator.page(1).object_list
        resp = {'data': data_list, 'totalCount': paginator.count}
        return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')  # 查询次数
def VisitStatus(request):
    data = ujson.loads(request.body.decode('utf-8'))
    page = data.get('pageNum')  # 必须
    pageSize = data.get('pageSize')  # 必须
    userid = data.get('userid')  # 必须
    user1 = user.objects.get(id=userid)
    companyname = ""
    startTime = "1979-09-09"
    endTime = "2999-09-09"
    creatname = ""
    prefix = ""
    if data.get('companyName'):
        companyname = data.get('companyname')
    if data.get('prefix'):
        prefix = data.get('prefix')
    if data.get('creatname'):
        creatname = data.get('creatname')
    if data.get('startTime'):
        startTime = data.get('startTime')
    if data.get('endTime'):
        endTime = data.get('endTime')
    if user1.verify == 2:
        handles1 = handles.objects.filter(username__contains=creatname, perix__contains=prefix,
                                          company__contains=companyname,
                                          time__lte=endTime, time__gte=startTime).values('id', 'username', 'perix',
                                                                                         'time', 'company', 'server_id','count')
        paginator = Paginator(handles1, pageSize)
        if page:
            data_list = paginator.page(page).object_list
        else:
            data_list = paginator.page(1).object_list

        resp = {'data': data_list, 'totalCount': paginator.count}
        return HttpResponse(ujson.dumps(resp))
    if user1.verify == 1:
        handles1 = handles.objects.filter(username=user1.username, perix__contains=prefix,
                                          company__contains=companyname,
                                          time__lte=endTime, time__gte=startTime).values('id', 'username', 'perix',
                                                                                         'time', 'company', 'server_id','count')
        paginator = Paginator(handles1, pageSize)
        if page:
            data_list = paginator.page(page).object_list
        else:
            data_list = paginator.page(1).object_list
        resp = {'data': data_list, 'totalCount': paginator.count}
        return HttpResponse(ujson.dumps(resp))



@auth_permission_required('handleProjectVue.user')  # 修改handle数据
def UpdatehHandle(request):
    response = ujson.loads(request.body.decode('utf-8'))
    perfix = response.get('prefix')
    handle1 = handles.objects.get(perix=perfix)
    data = response.get('Data')
    record.index = []
    record.type = []
    record.value = []
    for i in data:
        record.index.append(i.get('index'))
        record.type.append(i.get('type'))
        record.value.append(i.get('data'))
    delete(perfix, handle1.server.ip, handle1.server.port)
    createh(record, perfix, handle1.server.ip, handle1.server.port)
    resp = {'status': 1, 'message': "修改成功"}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')  # 修改注册服务器
def UpdateServer(request):
    response = ujson.loads(request.body.decode('utf-8'))
    prefix = response.get('prefix')
    serverid = response.get('serverid')
    handle = handles.objects.get(perix=prefix)
    handle_record = reslove(prefix, handle.server.ip, handle.server.port)
    handle1 = None
    handle1 = analyze_json(handle_record)
    handle1.context.pop()
    record.index = []
    record.index = []
    record.value = []
    for i in range(len(handle1.context)):
        print i
        record.index.append(handle1.context[i].get('index'))
        record.type.append(handle1.context[i].get('type'))
        record.value.append(handle1.context[i].get('datas'))
    print record.value
    delete(prefix, handle.server.ip, handle.server.port)
    server2 = server.objects.get(id=serverid)
    handles.objects.filter(perix=prefix).update(server=server2)
    createh(record, prefix, server2.ip, server2.port)
    resp = {'status': 1, 'message': "修改成功"}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')  # 删除数据
def DelHandle(request):
    response = ujson.loads(request.body.decode('utf-8'))
    perfix = response.get('prefix')
    handle1 = handles.objects.get(perix=perfix)
    delete(perfix, handle1.server.ip, handle1.server.port)
    handle1 = handles.objects.filter(perix=perfix).delete()
    resp = {'status': 1, 'message': "删除成功"}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')  # 注册量
def creatCount(request):
    response = ujson.loads(request.body.decode('utf-8'))
    id = response.get('id')
    now = django.utils.timezone.datetime.now()
    start = now - relativedelta(days=12)
    print now
    print start
    # 当前时间
    # 获取近一年内数据
    data = handles.objects.filter(time__range=(start, now), server=id)
    res = data.extra(select={'year': 'year(time)', 'month': 'month(time)', 'day': 'day(time)'}).values('year', 'month',
                                                                                                       'day').annotate(
        count=Count('time')).order_by()
    print res
    res_data = []
    for item in res:
        res_data.append({
            'time': str(item.get('year')) + "-" + str(item.get('month')) + "-" + str(item.get('day')),
            'count': item.get('count')
        })
    print res_data
    resp = {'status': 1, 'data': res_data}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')
def resolveCount(request):
    response = ujson.loads(request.body.decode('utf-8'))
    id = response.get('id')
    server1 = server.objects.get(id=id)
    now = django.utils.timezone.datetime.now()
    start = now - relativedelta(days=12)
    # 当前时间
    # 获取近一年内数据
    data = resolveRecord.objects.filter(time__range=(start, now), ip=server1.ip)
    res = data.extra(select={'year': 'year(time)', 'month': 'month(time)', 'day': 'day(time)'}).values('year', 'month',
                                                                                                       'day').annotate(
        count=Count('time')).order_by()
    print res
    res_data = []
    for item in res:
        res_data.append({
            'time': str(item.get('year')) + "-" + str(item.get('month')) + "-" + str(item.get('day')),
            'count': item.get('count')
        })

    print res_data
    resp = {'status': 1, 'data': res_data}
    return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')
def responseSuccess(request):
    response = ujson.loads(request.body.decode('utf-8'))
    id = response.get('id')
    server1 = server.objects.get(id=id)
    now = django.utils.timezone.datetime.now()
    start = now - relativedelta(days=7)
    # 当前时间
    # 获取近一年内数据
    data = resolveRecord.objects.filter(time__range=(start, now), success=0, ip=server1.ip).count()
    data1 = resolveRecord.objects.filter(time__range=(start, now), success=1, ip=server1.ip).count()
    print data
    print data1
    if data1 == 0 & data == 0:
        resp = {'status': 0, 'data': 0}
        return HttpResponse(ujson.dumps(resp))
    else:

        resp = {'status': 1, 'data': (format(float(data1) / float(data+data1), '.2f'))}
        return HttpResponse(ujson.dumps(resp))


@auth_permission_required('handleProjectVue.user')
def hardWare(request):
    response = ujson.loads(request.body.decode('utf-8'))
    id = response.get('id')
    server1 = server.objects.get(id=id)
    data = serverquery.config(server1.ip, 22, server1.username, server1.password)
    resp = {'status': 1, 'data': data}
    return HttpResponse(ujson.dumps(resp))
