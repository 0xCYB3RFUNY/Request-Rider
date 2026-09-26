from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("lab", "0006_remove_appsettings")]

    operations = [migrations.DeleteModel(name="AuditLog")]
