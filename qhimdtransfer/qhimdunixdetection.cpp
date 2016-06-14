#include "qhimdunixdetection.h"
#include <QVariantList>
#include <QDebug>
#include <QFileDialog>
#include <QMessageBox>
#include <QApplication>

#if (QT_MAJOR_VERSION > 4)
    class Sleeper : public QThread {};
#else
/* helper function for QThread::msleep(), this is a protected member in Qt4 */
class Sleeper : public QThread {
public:
   void msleep(int ms) { QThread::msleep(ms); }
};
#endif

QHiMDDetection * createDetection(QObject * parent)
{
    return new QHiMDUnixDetection(parent);
}

/* following static functions are stolen from qtdbusutil.cpp, return value of get_property() for the mountpoint is an array of QByteArrays,
 * cropped unneeded parts, characters and spaces here and changed the output character type from QString::number() to QChar
 * */
static bool argToString(const QDBusArgument &busArg, QString &out);

static bool variantToString(const QVariant &arg, QString &out)
{
    int argType = arg.userType();

     if (argType == QVariant::ByteArray)
     {
        QByteArray list = arg.toByteArray();
        for (int i = 0; i < list.count(); ++i)
            out += QChar(list.at(i));
    }
    else if (argType == qMetaTypeId<QDBusArgument>())
     {
        argToString(qvariant_cast<QDBusArgument>(arg), out);
     }
    else if (argType == qMetaTypeId<QDBusVariant>())
    {
        const QVariant v = qvariant_cast<QDBusVariant>(arg).variant();

        if (!variantToString(v, out))
            return false;
    }
    return true;
}

static bool argToString(const QDBusArgument &busArg, QString &out)
{
    bool doIterate = false;
    QDBusArgument::ElementType elementType = busArg.currentType();

    switch (elementType)
    {
        case QDBusArgument::BasicType:
        case QDBusArgument::VariantType:
            if (!variantToString(busArg.asVariant(), out))
                return false;
            break;
        case QDBusArgument::ArrayType:
            busArg.beginArray();
            doIterate = true;
            break;
        case QDBusArgument::UnknownType:
        default:
            return false;
    }

    if (doIterate && !busArg.atEnd()) {
        while (!busArg.atEnd()) {
            if (!argToString(busArg, out))
                return false;
            out += QLatin1String(" , ");
        }
        out.chop(3);
    }

    if(elementType == QDBusArgument::ArrayType)
        busArg.endArray();
    return true;
}

QHiMDUnixDetection::QHiMDUnixDetection(QObject *parent)
  : QHiMDDetection(parent), had(new QHiMDAdaptor(this)),
    dbus_sys(QDBusConnection::connectToBus( QDBusConnection::SystemBus, "system" ) ),
    dbus_ses(QDBusConnection::connectToBus(QDBusConnection::SessionBus, "com.trolltech.Qt"))
{
    if(!dbus_sys.isConnected())
        qDebug() << tr("cannot connect to system bus");
    if(!dbus_ses.isConnected())
        qDebug() << tr("cannot connect to session bus");

    if(!dbus_ses.registerObject("/QHiMDUnixDetection", this, QDBusConnection::ExportAllSlots))
        qDebug() << tr("cannot register dbus interface object ");

    // register interface to session bus to make it visible to all other connections
    dbus_ses.interface()->registerService("com.trolltech.Qt");
    dbus_ses.interface()->startService("com.trolltech.Qt");

    // now connect method calls to our slots
    QDBusConnection::sessionBus().connect("com.trolltech.Qt", "/com/trolltech/Qt/QHiMDUnixDetection", "com.trolltech.Qt", "AddMDDevice", this, SLOT(AddMDDevice(QString, int, int)));
    QDBusConnection::sessionBus().connect("com.trolltech.Qt", "/com/trolltech/Qt/QHiMDUnixDetection", "com.trolltech.Qt", "RemoveMDDevice", this, SLOT(RemoveMDDevice(QString,int,int)));
}

QVariant QHiMDUnixDetection::get_property(QString udiskPath, QString property, QString interface)
{
    QDBusMessage msg = QDBusMessage::createMethodCall(UDISK_SERVICE, udiskPath, UDISK_PROPERTIES, "Get");
    QList<QVariant> args;
    QDBusMessage reply;

    /* set arguments */
    args.append(interface);
    args.append(property);
    msg.setArguments(args);

    /* send message */
    reply = dbus_sys.call(msg);

    if (!reply.signature().compare(QString(QChar('v'))) && reply.arguments().length() >0)
        return reply.arguments().at(0);
    else
        return QVariant();
}

QString QHiMDUnixDetection::mountpoint(QString devpath)
{
    QString udev_path = UDISK_DEVICE_PATH;
    QVariant ret;
    QString mp;

    // setup correct path for UDisk operations, just need sd* instead fo /dev/sd*
    devpath.remove(0, devpath.lastIndexOf("/")+1);
    udev_path.append(devpath);

    ret = get_property(udev_path, PROP_MOUNTPATH, UDISK_FILESYSTEM);
    if(!ret.isValid())
        return QString();

    /* try to read mountpoint as string
     * as this is an array of /0 terminatined ByteArrays it returns first mointpoint only because of the terminating /0 character
     * this is fine for now and matches our needs
     */
    if(!variantToString(ret, mp))
        return QString();

    return mp;
}

QMDDevice *QHiMDUnixDetection::find_by_deviceFile(QString file)
{
    QMDDevice * mddev;

    foreach(mddev, dlist)
    {
        if(mddev->deviceFile() == file)
            return mddev;
    }
    return NULL;
}

void QHiMDUnixDetection::add_himddevice(QString file, QString name)
{
    if (find_by_deviceFile(file))
        return;

    QHiMDDevice * new_device = new QHiMDDevice();

    new_device->setDeviceFile(file);
    new_device->setBusy(false);
    new_device->setPath(QString());
    new_device->setName(name);
    new_device->setMdInserted(false);

    dlist.append(new_device);
    emit deviceListChanged(dlist);
}

void QHiMDUnixDetection::remove_himddevice(QString file)
{
    int index = -1;
    QMDDevice * dev;

    if (!(dev = find_by_deviceFile(file)))
        return;

    index = dlist.indexOf(dev);

    if(dev->isOpen())
        dev->close();

    delete dev;
    dev = NULL;

    dlist.removeAt(index);

    emit deviceListChanged(dlist);
}

void QHiMDUnixDetection::AddMDDevice(QString deviceFile, int vid, int pid)
{
    QString name = QString(identify_usb_device(vid, pid));
    Sleeper slp;

    // check if this is valid minidisc device depending on vendor and product id, for all known devices identify_usb_device() should return a name
    if(name.isEmpty())
        return;

    /* check if it is a netmd device, reenumerate netmd devices at this point to make libnetmd find it
     */
    if(name.contains("NetMD"))
    {
        qDebug() << tr("qhimdtransfer detection: netmd device detected: %1").arg(name);
        slp.msleep(10000); // wait for TOC to be loaded by the device, else tracklist may not by shown correctly (no tiltles, unknown codec etc.)
        rescan_netmd_devices();
        return;
    }

    // check if driver file is /dev/sd*, this is what we need, for future use (formating etc.) also check for /dev/sg* scsi driver file
    if(!deviceFile.startsWith("/dev/sd"))
        return;

    qDebug() << tr("qhimdtransfer detection: himd device detected at %1: %2").arg(deviceFile).arg(name);

    /* if mountpoint detection fails ask user to provide mountpoint with a QFileDialog
    if(mountpt.isEmpty())
        return;*/

    add_himddevice(deviceFile,name);

}

void QHiMDUnixDetection::RemoveMDDevice(QString deviceFile, int vid, int pid)
{
    QString name = QString(identify_usb_device(vid, pid));

    // check if this is valid minidisc device, for all known devices identify_usb_device() should return a name
    if(name.isEmpty())
        return;

    if(name.contains("NetMD"))
    {
        qDebug() << tr("qhimdtransfer detection: netmd device removed: %1").arg(name);
        rescan_netmd_devices();
        return;
    }

    // check if driver file is /dev/sd*, this is what we need, for future use (formating etc.) also check for /dev/sg* scsi driver file
    if(!deviceFile.startsWith("/dev/sd"))
        return;

    qDebug() << tr("qhimdtransfer detection: himd device removed at %1: %2").arg(deviceFile).arg(name);

    remove_himddevice(deviceFile);
}

