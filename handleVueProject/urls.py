from django.conf.urls import url
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token

from . import views

app_name = 'handleVueProject'
urlpatterns = [
    url(r'^register/', views.register),
    url(r'^login/', obtain_jwt_token),
    url(r'^userSelect/', views.userSelect),
    url(r'^userDelete/', views.userDelete),
    url(r'^userUpdate/', views.userUpdate),
    url(r'^userVerify/', views.userVerify),
    url(r'^userRefuse/', views.userRefuse),
    url(r'^userAccept/', views.userAccept),
    url(r'^alterPassword/', views.alterPassword),
    url(r'^downVerify/', views.downVerify),
    url(r'^ServerList/', views.ServerList),
    url(r'^Classifiedquery/', views.Classifiedquery),
    url(r'^CreateHandle/', views.CreateHandle),
    url(r'^ExcelDownload/', views.Download),
    url(r'^ExcelUpload/', views.upload_file),
    url(r'^OneQuery/', views.OneQuery),
    url(r'^ManyQuery/', views.ManyQuery),
    url(r'^UpdatehHandle/', views.UpdatehHandle),
    url(r'^UpdateServer/', views.UpdateServer),
    url(r'^DelHandle/', views.DelHandle),
    url(r'creatCount/', views.creatCount),
    url(r'^VisitStatus/', views.VisitStatus),
    url(r'^downVerify1/', views.downVerify1),
    url(r'^resolveCount/', views.resolveCount),
    url(r'^responseSuccess/', views.responseSuccess),
    url(r'^hardWare/', views.hardWare),
]
