from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("lab", "0002_appsettings")]
    operations = [migrations.DeleteModel(name="AppSettings")]
