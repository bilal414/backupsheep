from django.db import models


class UtilCountry(models.Model):
    code = models.CharField(max_length=2, null=True)
    name = models.CharField(max_length=45, null=True)
    iso_alpha3 = models.CharField(max_length=3, null=True)
    priority = models.IntegerField(default=0)

    class Meta:
        db_table = "util_country"


class UtilSetting(models.Model):
    running_storage_billing = models.BooleanField(null=True)
    running_storage_calculation = models.BooleanField(null=True)

    class Meta:
        db_table = "util_setting"


class UtilBase(models.Model):
    def __str__(self):
        return "%s " % self.name

    name = models.CharField(max_length=255, null=True)

    class Meta:
        abstract = True


class UtilAttribute(models.Model):
    def __str__(self):
        return "%s " % self.name

    name = models.CharField(max_length=255, null=True)
    code = models.CharField(max_length=64, unique=True)

    class Meta:
        abstract = True


class UtilProfileFull(models.Model):
    email = models.EmailField()
    first_name = models.CharField(max_length=64, null=True)
    last_name = models.CharField(max_length=64, null=True)
    phone_country_code = models.CharField(max_length=6, null=True)
    phone_number = models.CharField(max_length=16, null=True)
    country = models.CharField(max_length=64, null=True)
    address1 = models.CharField(max_length=1024, null=True)
    address2 = models.CharField(max_length=1024, null=True)
    city = models.CharField(max_length=64, null=True)
    zip_code = models.CharField(max_length=64, null=True)
    state = models.CharField(max_length=64, null=True)
    created = models.BigIntegerField()
    modified = models.BigIntegerField()

    class Meta:
        abstract = True

    @property
    def phone(self):
        return "%s%s" % (self.phone_country_code, self.phone_number)

    @property
    def full_name(self):
        """Returns the person's full name."""
        return "%s %s" % (self.first_name, self.last_name)

    @property
    def full_address(self):
        """Returns the person's full address."""
        return "%s%s%s%s%s" % (
            self.address1 + ", " if self.address1 else "",
            self.address2 + ", " if self.address2 else "",
            self.city + ", " if self.city else "",
            self.state + ", " if self.state else "",
            self.zip_code + "" if self.zip_code else "",
        )


class UtilAuth(models.Model):
    email_token = models.CharField(null=True, max_length=64, blank=True)
    password_token = models.CharField(null=True, max_length=64, blank=True)
    email_verified = models.BooleanField(default=False)
    send_pass_reset_email = models.BooleanField(default=False)

    class Meta:
        abstract = True


class UtilStatus(UtilAttribute):
    class Meta:
        db_table = 'util_status'
        verbose_name = "Status"
        verbose_name_plural = "Status"


class UtilTotal(models.Model):
    all_eligible_total = models.DecimalField(max_digits=16, decimal_places=2, null=True)

    class Meta:
        db_table = 'util_total'
        verbose_name = "Util Total"
        verbose_name_plural = "Util Totals"
