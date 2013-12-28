#include "qhimdunixdetection.h"
#include <QVariantList>
#include <QDebug>
#include <QApplication>

QHiMDDetection * createDetection(QObject * parent)
{
    return new QHiMDUnixDetection(parent);
}

QHiMDUnixDetection::QHiMDUnixDetection(QObject *parent)
  : QHiMDDetection(parent), had(new QHiMDAdaptor(this)),
    dbus_sys(QDBusConnection::connectToBus( QDBusConnection::SystemBus, "system" ) ),
    dbus_ses(QDBusConnection::connectToBus(QDBusConnection::SessionBus, "com.trolltech.Qt"))
{
    if(!dbus_sys.isConnected())
        qDebug() << "cannot connect to system bus";
    if(!dbus_ses.isConnected())
        qDebug() << "cannot connect to session bus";

    if(!dbus_ses.registerObject("/QHiMDUnixDetection", this, QDBusConnection::ExportAllSlots))
        qDebug() << "cannot register dbus interface object ";

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
    QVariant var;
    QList<QVariant> args;
    QDBusMessage reply;

    /* set arguments */
    args.append(interface);
    args.append(property);
    msg.setArguments(args);

    /* send message */
    reply = dbus_sys.call(msg);

    if (!reply.signature().compare(QString(QChar('v'))) && reply.arguments().length() >0)
            var = reply.arguments().at(0);
    else
        return QVariant();

    return var;
}

QString QHiMDUnixDetection::mountpoint(QString devpath)
{
    QString udev_path = UDISK_DEVICE_PATH;
    QVariant mp;

    // setup correct path for UDisk operations, just need sd* instead fo /dev/sd*
    devpath.remove(0, devpath.lastIndexOf("/")+1);
    udev_path.append(devpath);

    /* TODO: convert return value of get_property() in order to extract needed data, the returned value is marked as INVALID and cannot be converted,
     * it should contain something like this (this is a sample of what qdbusviewer returns, here: "/media/man2/disk"):
     *         Arguments: [Variant: [Argument: aay {{47, 109, 101, 100, 105, 97, 47, 109, 97, 110, 50, 47, 100, 105, 115, 107, 0}}]]
     * so we have to convert the udev "aay" format (array of filepaths) to something readable
     */
    mp = get_property(udev_path, PROP_MOUNTPATH, UDISK_FILESYSTEM);
    return mp.toString();
}

void QHiMDUnixDetection::AddMDDevice(QString deviceFile, int vid, int pid)
{
    QString mountpt;
    QString name = QString(identify_usb_device(vid, pid));

    // check if this is valid minidisc device depending on vendor and product id, for all known devices identify_usb_device() should return a name
    if(name.isEmpty())
        return;

    /* check if it is a netmd device, reenumerate netmd devices at this point to make libnetmd find it
     */
    if(name.contains("NetMD"))
    {
        qDebug() << "qhimdtransfer detection: netmd device detected: " + name;
        QThread::msleep(5000); // wait for TOC to be loaded by the device, else tracklist may by shown correctly (no tiltles, unknown codec etc.)
        rescan_netmd_devices();
        return;
    }

    // check if driver file is /dev/sd*, this is what we need, for future use (formating etc.) also check for /dev/sg* scsi driver file
    if(!deviceFile.startsWith("/dev/sd"))
        return;


    qDebug() << QString("qhimdtransfer detection: himd device detected at %1: %2").arg(deviceFile).arg(name);

    // wait for device to be mounted by polling for mountpoint, this could take some time
    // break if mount process did not finish within 30 seconds
    for(int i = 0; i < 30; i++)
    {
        QThread::msleep(1000);
        QApplication::processEvents();  // prevent application to be blocked completely
        if(!(mountpt = mountpoint(deviceFile)).isEmpty())
                break;
    }
    qDebug() << (mountpt.isEmpty() ? "no mountpoint detected" : QString("device mounted at: %1").arg(mountpt));

    /* TODO: add new QHiMDDevice object to device list here,
     * as mountpoint() function does not work correctly yet, this cannot be done at current stage of the code
     */

}

void QHiMDUnixDetection::RemoveMDDevice(QString deviceFile, int vid, int pid)
{
    QString name = QString(identify_usb_device(vid, pid));

    // check if this is valid minidisc device, for all known devices identify_usb_device() should return a name
    if(name.isEmpty())
        return;

    if(name.contains("NetMD"))
    {
        qDebug() << "qhimdtransfer detection: netmd device removed: " + name;
        rescan_netmd_devices();
        return;
    }

    // check if driver file is /dev/sd*, this is what we need, for future use (formating etc.) also check for /dev/sg* scsi driver file
    if(!deviceFile.startsWith("/dev/sd"))
        return;

    qDebug() << QString("qhimdtransfer detection: himd device removed at %1: %2").arg(deviceFile).arg(name);

    /* TODO: remove corresponding QHiMDDevice object from device list here */

}

