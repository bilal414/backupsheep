from django.db import models
from model_utils.models import TimeStampedModel

from apps.console.account.models import CoreAccountGroup
from apps.console.utils.models import UtilBase, UtilTag


class CoreProject(UtilBase):
    def __str__(self):
        return f'{self.name}'

    class Type(models.IntegerChoices):
        INTERNAL = 0, 'Internal'
        CLIENT = 1, 'Client'

    class Status(models.IntegerChoices):
        ACTIVE = 1, 'Active'
        PAUSED = 0, 'Paused'

    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    type = models.IntegerField(choices=Type.choices, null=True)
    tags = models.ManyToManyField(UtilTag, related_name='projects')
    groups = models.ManyToManyField(CoreAccountGroup, related_name='projects', through='CoreProjectGroup')

    class Meta:
        db_table = 'core_project'
        verbose_name = "Project"
        verbose_name_plural = "Projects"


class CoreProjectGroup(TimeStampedModel):
    project = models.ForeignKey(CoreProject, on_delete=models.PROTECT)
    group = models.ForeignKey(CoreAccountGroup, on_delete=models.PROTECT)

    class Meta:
        db_table = 'core_project_mtm_group'
        verbose_name = 'Project Group'
        verbose_name_plural = 'Project Groups'
