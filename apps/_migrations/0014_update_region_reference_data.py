"""Bring provider region reference data up to date on EXISTING installs.

0007_seed_reference_data only runs get_or_create on deploys that already applied it,
so rows added/changed in reference_data.json since then never reach existing databases.
This migration upserts (update_or_create by the unique `code`) just the delta:

  - CoreWasabiRegion  : was never seeded -- all 16 current regions
  - CoreAlibabaRegion : was never seeded -- current OSS regions and endpoints
  - CoreDoSpacesRegion: sfo3, lon1, tor1, blr1, syd1, atl1, ric1, mkc1
  - CoreExoscaleRegion: at-vie-2, hr-zag-1
  - CoreIBMRegion     : eu-es, ca-mon, in-che, in-mum (mil01 is decommissioned; existing
                        mil01 rows are left untouched, it is only no longer seeded)
  - CoreIonosRegion   : endpoints moved from s3-<region> to s3.<region> hostnames;
                        added eu-central-3, eu-central-4, us-central-1
  - CoreTencentRegion : me-saudi-arabia, sa-saopaulo (ap-mumbai and na-toronto are
                        retired; existing rows are left untouched)
  - CoreOracleRegion  : us-chicago-1, ap-singapore-2, me-riyadh-1, sa-valparaiso-1,
                        sa-bogota-1, ap-batam-1, eu-turin-1, ap-kulai-2, mx-monterrey-1,
                        af-casablanca-1, eu-madrid-3
  - CoreRackCorpRegion: th, jp, sg, de, us, us-east-1, us-west-1, nz, au-nsw, au-qld,
                        au-vic, au-wa, global
  - CoreFilebaseRegion: endpoint s3.filebase.com -> s3.filebase.io, region code
                        us-east-1 -> auto (existing us-east-1 row is renamed in place,
                        keeping its id so PROTECT references stay valid)
  - CoreAWSRegion     : ap-south-2, ap-southeast-4, ap-southeast-5, eu-south-2,
                        eu-central-2, il-central-1, ca-west-1, mx-central-1

Nothing is deleted; idempotent, so re-running never duplicates rows.
"""
from django.db import migrations

ROWS = {
    "CoreWasabiRegion": [
        {"code": "us-east-1", "name": "US East 1 (N. Virginia)", "endpoint": "s3.wasabisys.com"},
        {"code": "us-east-2", "name": "US East 2 (N. Virginia)", "endpoint": "s3.us-east-2.wasabisys.com"},
        {"code": "us-central-1", "name": "US Central 1 (Texas)", "endpoint": "s3.us-central-1.wasabisys.com"},
        {"code": "us-west-1", "name": "US West 1 (Oregon)", "endpoint": "s3.us-west-1.wasabisys.com"},
        {"code": "us-west-2", "name": "US West 2 (San Jose)", "endpoint": "s3.us-west-2.wasabisys.com"},
        {"code": "ca-central-1", "name": "CA Central 1 (Toronto)", "endpoint": "s3.ca-central-1.wasabisys.com"},
        {"code": "eu-central-1", "name": "EU Central 1 (Amsterdam)", "endpoint": "s3.eu-central-1.wasabisys.com"},
        {"code": "eu-central-2", "name": "EU Central 2 (Frankfurt)", "endpoint": "s3.eu-central-2.wasabisys.com"},
        {"code": "eu-west-1", "name": "EU West 1 (United Kingdom)", "endpoint": "s3.eu-west-1.wasabisys.com"},
        {"code": "eu-west-2", "name": "EU West 2 (Paris)", "endpoint": "s3.eu-west-2.wasabisys.com"},
        {"code": "eu-west-3", "name": "EU West 3 (United Kingdom)", "endpoint": "s3.eu-west-3.wasabisys.com"},
        {"code": "eu-south-1", "name": "EU South 1 (Milan)", "endpoint": "s3.eu-south-1.wasabisys.com"},
        {"code": "ap-northeast-1", "name": "AP Northeast 1 (Tokyo)", "endpoint": "s3.ap-northeast-1.wasabisys.com"},
        {"code": "ap-northeast-2", "name": "AP Northeast 2 (Osaka)", "endpoint": "s3.ap-northeast-2.wasabisys.com"},
        {"code": "ap-southeast-1", "name": "AP Southeast 1 (Singapore)", "endpoint": "s3.ap-southeast-1.wasabisys.com"},
        {"code": "ap-southeast-2", "name": "AP Southeast 2 (Sydney)", "endpoint": "s3.ap-southeast-2.wasabisys.com"},
    ],
    "CoreAlibabaRegion": [
        {"code": "cn-hangzhou", "name": "China (Hangzhou)", "endpoint": "oss-cn-hangzhou.aliyuncs.com"},
        {"code": "cn-shanghai", "name": "China (Shanghai)", "endpoint": "oss-cn-shanghai.aliyuncs.com"},
        {"code": "cn-nanjing", "name": "China (Nanjing - Local Region)", "endpoint": "oss-cn-nanjing.aliyuncs.com"},
        {"code": "cn-qingdao", "name": "China (Qingdao)", "endpoint": "oss-cn-qingdao.aliyuncs.com"},
        {"code": "cn-beijing", "name": "China (Beijing)", "endpoint": "oss-cn-beijing.aliyuncs.com"},
        {"code": "cn-zhangjiakou", "name": "China (Zhangjiakou)", "endpoint": "oss-cn-zhangjiakou.aliyuncs.com"},
        {"code": "cn-huhehaote", "name": "China (Hohhot)", "endpoint": "oss-cn-huhehaote.aliyuncs.com"},
        {"code": "cn-wulanchabu", "name": "China (Ulanqab)", "endpoint": "oss-cn-wulanchabu.aliyuncs.com"},
        {"code": "cn-shenzhen", "name": "China (Shenzhen)", "endpoint": "oss-cn-shenzhen.aliyuncs.com"},
        {"code": "cn-heyuan", "name": "China (Heyuan)", "endpoint": "oss-cn-heyuan.aliyuncs.com"},
        {"code": "cn-guangzhou", "name": "China (Guangzhou)", "endpoint": "oss-cn-guangzhou.aliyuncs.com"},
        {"code": "cn-chengdu", "name": "China (Chengdu)", "endpoint": "oss-cn-chengdu.aliyuncs.com"},
        {"code": "cn-hongkong", "name": "China (Hong Kong)", "endpoint": "oss-cn-hongkong.aliyuncs.com"},
        {"code": "ap-northeast-1", "name": "Japan (Tokyo)", "endpoint": "oss-ap-northeast-1.aliyuncs.com"},
        {"code": "ap-northeast-2", "name": "South Korea (Seoul)", "endpoint": "oss-ap-northeast-2.aliyuncs.com"},
        {"code": "ap-southeast-1", "name": "Singapore", "endpoint": "oss-ap-southeast-1.aliyuncs.com"},
        {"code": "ap-southeast-3", "name": "Malaysia (Kuala Lumpur)", "endpoint": "oss-ap-southeast-3.aliyuncs.com"},
        {"code": "ap-southeast-5", "name": "Indonesia (Jakarta)", "endpoint": "oss-ap-southeast-5.aliyuncs.com"},
        {"code": "ap-southeast-6", "name": "Philippines (Manila)", "endpoint": "oss-ap-southeast-6.aliyuncs.com"},
        {"code": "ap-southeast-7", "name": "Thailand (Bangkok)", "endpoint": "oss-ap-southeast-7.aliyuncs.com"},
        {"code": "eu-central-1", "name": "Germany (Frankfurt)", "endpoint": "oss-eu-central-1.aliyuncs.com"},
        {"code": "eu-west-1", "name": "UK (London)", "endpoint": "oss-eu-west-1.aliyuncs.com"},
        {"code": "us-west-1", "name": "US (Silicon Valley)", "endpoint": "oss-us-west-1.aliyuncs.com"},
        {"code": "us-east-1", "name": "US (Virginia)", "endpoint": "oss-us-east-1.aliyuncs.com"},
        {"code": "na-south-1", "name": "Mexico", "endpoint": "oss-na-south-1.aliyuncs.com"},
        {"code": "me-east-1", "name": "UAE (Dubai)", "endpoint": "oss-me-east-1.aliyuncs.com"},
        {"code": "me-central-1", "name": "SAU (Riyadh - Partner Region)", "endpoint": "oss-me-central-1.aliyuncs.com"},
    ],
    "CoreAWSRegion": [
        {"code": "ap-south-2", "name": "Asia Pacific (Hyderabad)", "endpoint": "ec2.ap-south-2.amazonaws.com", "rds_endpoint": "rds.ap-south-2.amazonaws.com", "s3_endpoint": None},
        {"code": "ap-southeast-4", "name": "Asia Pacific (Melbourne)", "endpoint": "ec2.ap-southeast-4.amazonaws.com", "rds_endpoint": "rds.ap-southeast-4.amazonaws.com", "s3_endpoint": None},
        {"code": "ap-southeast-5", "name": "Asia Pacific (Malaysia)", "endpoint": "ec2.ap-southeast-5.amazonaws.com", "rds_endpoint": "rds.ap-southeast-5.amazonaws.com", "s3_endpoint": None},
        {"code": "eu-south-2", "name": "Europe (Spain)", "endpoint": "ec2.eu-south-2.amazonaws.com", "rds_endpoint": "rds.eu-south-2.amazonaws.com", "s3_endpoint": None},
        {"code": "eu-central-2", "name": "Europe (Zurich)", "endpoint": "ec2.eu-central-2.amazonaws.com", "rds_endpoint": "rds.eu-central-2.amazonaws.com", "s3_endpoint": None},
        {"code": "il-central-1", "name": "Israel (Tel Aviv)", "endpoint": "ec2.il-central-1.amazonaws.com", "rds_endpoint": "rds.il-central-1.amazonaws.com", "s3_endpoint": None},
        {"code": "ca-west-1", "name": "Canada West (Calgary)", "endpoint": "ec2.ca-west-1.amazonaws.com", "rds_endpoint": "rds.ca-west-1.amazonaws.com", "s3_endpoint": None},
        {"code": "mx-central-1", "name": "Mexico (Central)", "endpoint": "ec2.mx-central-1.amazonaws.com", "rds_endpoint": "rds.mx-central-1.amazonaws.com", "s3_endpoint": None},
    ],
    "CoreDoSpacesRegion": [
        {"code": "sfo3", "name": "San Francisco", "endpoint": "sfo3.digitaloceanspaces.com"},
        {"code": "lon1", "name": "London", "endpoint": "lon1.digitaloceanspaces.com"},
        {"code": "tor1", "name": "Toronto", "endpoint": "tor1.digitaloceanspaces.com"},
        {"code": "blr1", "name": "Bangalore", "endpoint": "blr1.digitaloceanspaces.com"},
        {"code": "syd1", "name": "Sydney", "endpoint": "syd1.digitaloceanspaces.com"},
        {"code": "atl1", "name": "Atlanta", "endpoint": "atl1.digitaloceanspaces.com"},
        {"code": "ric1", "name": "Richmond", "endpoint": "ric1.digitaloceanspaces.com"},
        {"code": "mkc1", "name": "Kansas City", "endpoint": "mkc1.digitaloceanspaces.com"},
    ],
    "CoreExoscaleRegion": [
        {"code": "at-vie-2", "name": "Austria - Vienna (at-vie-2)", "endpoint": "sos-at-vie-2.exo.io"},
        {"code": "hr-zag-1", "name": "Croatia - Zagreb (hr-zag-1)", "endpoint": "sos-hr-zag-1.exo.io"},
    ],
    "CoreIBMRegion": [
        {"code": "eu-es", "name": "eu-es"},
        {"code": "ca-mon", "name": "ca-mon"},
        {"code": "in-che", "name": "in-che"},
        {"code": "in-mum", "name": "in-mum"},
    ],
    "CoreIonosRegion": [
        {"code": "de", "name": "Frankfurt, Germany (EU Central)", "endpoint": "s3.eu-central-1.ionoscloud.com"},
        {"code": "eu-central-2", "name": "Berlin, Germany (EU Central)", "endpoint": "s3.eu-central-2.ionoscloud.com"},
        {"code": "eu-south-2", "name": "Logrono, Spain (EU South)", "endpoint": "s3.eu-south-2.ionoscloud.com"},
        {"code": "eu-central-3", "name": "Berlin, Germany (EU Central)", "endpoint": "s3.eu-central-3.ionoscloud.com"},
        {"code": "eu-central-4", "name": "Frankfurt, Germany (EU Central)", "endpoint": "s3.eu-central-4.ionoscloud.com"},
        {"code": "us-central-1", "name": "Lenexa, USA (US Central)", "endpoint": "s3.us-central-1.ionoscloud.com"},
    ],
    "CoreOracleRegion": [
        {"code": "us-chicago-1", "name": "US Midwest (Chicago)"},
        {"code": "ap-singapore-2", "name": "Singapore West (Singapore)"},
        {"code": "me-riyadh-1", "name": "Saudi Arabia Central (Riyadh)"},
        {"code": "sa-valparaiso-1", "name": "Chile West (Valparaiso)"},
        {"code": "sa-bogota-1", "name": "Colombia Central (Bogota)"},
        {"code": "ap-batam-1", "name": "Indonesia North (Batam)"},
        {"code": "eu-turin-1", "name": "Italy North (Turin)"},
        {"code": "ap-kulai-2", "name": "Malaysia West 2 (Kulai)"},
        {"code": "mx-monterrey-1", "name": "Mexico Northeast (Monterrey)"},
        {"code": "af-casablanca-1", "name": "Morocco West (Casablanca)"},
        {"code": "eu-madrid-3", "name": "Spain Central (Madrid 3)"},
    ],
    "CoreRackCorpRegion": [
        {"code": "th", "name": "Thailand"},
        {"code": "jp", "name": "Japan"},
        {"code": "sg", "name": "Singapore"},
        {"code": "de", "name": "Germany"},
        {"code": "us", "name": "United States"},
        {"code": "us-east-1", "name": "US East (New York)"},
        {"code": "us-west-1", "name": "US West (Fremont)"},
        {"code": "nz", "name": "New Zealand"},
        {"code": "au-nsw", "name": "Australia (NSW)"},
        {"code": "au-qld", "name": "Australia (QLD)"},
        {"code": "au-vic", "name": "Australia (VIC)"},
        {"code": "au-wa", "name": "Australia (Perth)"},
        {"code": "global", "name": "Global"},
    ],
    "CoreTencentRegion": [
        {"code": "me-saudi-arabia", "name": "Middle East (Riyadh)"},
        {"code": "sa-saopaulo", "name": "South America (Sao Paulo)"},
    ],
}


def update_region_reference_data(apps, schema_editor):
    CoreFilebaseRegion = apps.get_model("apps", "CoreFilebaseRegion")
    if not CoreFilebaseRegion.objects.filter(code="auto").exists():
        # Rename the legacy row in place (id stays, so PROTECT references hold).
        CoreFilebaseRegion.objects.filter(code="us-east-1").update(code="auto")
    CoreFilebaseRegion.objects.update_or_create(
        code="auto", defaults={"name": "Decentralized", "endpoint": "s3.filebase.io"}
    )

    for model_name, rows in ROWS.items():
        Model = apps.get_model("apps", model_name)
        for row in rows:
            Model.objects.update_or_create(
                code=row["code"], defaults={k: v for k, v in row.items() if k != "code"}
            )


class Migration(migrations.Migration):

    dependencies = [
        ("apps", "0012_restores"),
    ]

    operations = [
        # Reverse is a no-op: reference data is shared catalog, not user data, and region
        # rows are PROTECT-referenced by storage configs once created.
        migrations.RunPython(update_region_reference_data, migrations.RunPython.noop),
    ]
