# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.conf import settings


class user(AbstractUser):
    phonenumber = models.CharField(max_length=64)
    email = models.EmailField(max_length=256)
    card = models.CharField(max_length=64)
    filepath = models.CharField(max_length=256)
    verify = models.IntegerField(max_length=1)
    count = models.IntegerField(max_length=10)
    time = models.CharField(max_length=256)
    company = models.TextField(max_length=64)

    class Meta:
        db_table = 'user'

    @classmethod
    def create(cls, username, password, phonenumber, email, card, filepath, verify, count, time, companyname):
        user1 = cls(username=username, password=password, phonenumber=phonenumber, email=email, card=card,
                    filepath=filepath, verify=verify, count=count, time=time, company=companyname, is_staff=1, is_superuser=0)
        return user1

    def __str__(self):  # __unicode__ on Python 2
        return self.username


# 为每个用户添加token值
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


class handles(models.Model):
    username = models.CharField(max_length=64)
    perix = models.CharField(max_length=256)
    count = models.IntegerField(max_length=11)
    time = models.CharField(max_length=256)
    company = models.TextField(max_length=64)
    server = models.ForeignKey("server", on_delete=models.PROTECT)

    @classmethod
    def create(cls, company, username, perix, count, time, server):
        handles1 = cls(company=company, username=username, perix=perix, count=count, time=time, server=server)
        return handles1

    def __str__(self):              # __unicode__ on Python 2
        return self.perix


class server(models.Model):
    ip = models.CharField(max_length=64)
    port = models.IntegerField(max_length=64)
    username = models.CharField(max_length=64, null=True)
    password = models.CharField(max_length=256, null=True)

    @classmethod
    def create(cls, ip, username, password):
        server1 = cls(id=id, ip=ip, username=username, password=password)
        return server1

    def __str__(self):  # __unicode__ on Python 2
        return self.ip


class handle():
    perix = ""
    context = []


class record():
     index = []
     type = []
     value = []

