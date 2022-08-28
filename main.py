import dataclasses
import logging
import traceback
import sys
import os.path
import random
import time
import xml.etree.ElementTree
from socket import socket, AF_INET, SOCK_STREAM
import ssl
from ssl import SSLContext, SSLError, SSLSocket
from pprint import pprint
from threading import Thread, Event
from xml.etree import ElementTree
from paho.mqtt import client
from dataclasses import dataclass
from typing import Callable, Optional
from paho import mqtt
import socket
from samsung_discovery import SamsungDiscovery
import json
import select

logging.basicConfig(
    level='INFO',
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Wifi password for the SMARTAIRCON network is  JUNGFRAU2011 not 111112222 as specified on the user manual


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


@dataclass
class SamsungAirConditioner:
    mac_address: str
    ip_address: str
    nickname: str
    token: str
    base_topic: Optional[str] = '/'


class SamsungAirConditionerConfigParser(dict[str, SamsungAirConditioner]):
    def __init__(self, config_file: str = 'config.json'):
        self._config_file = config_file
        if not os.path.exists(config_file):
            return

        with open(config_file, 'r') as f:
            raw_config = f.read()
            if raw_config == '':
                return
            try:
                acs = json.loads(raw_config)
            except Exception as e:
                logging.error("Exception parsing json file> %s" % e)
                return
            for mac, ac in acs.items():
                self[mac] = (SamsungAirConditioner(**ac))

    def save(self):
        with open(self._config_file, 'w') as f:
            f.write(json.dumps(self, cls=EnhancedJSONEncoder, indent=4))


@dataclass
class SamsungACProperty:
    samsung_property: str
    access_type: str = 'RW'
    data_type: type = str
    value: str = ''
    mqtt_name: str = None

    def __post_init__(self):
        self.mqtt_name = self.mqtt_name or self.samsung_property


class SamsungACPropertyList(dict[SamsungACProperty]):
    """
    Manage the properties for the air conditioner.
    """
    def __init__(self, mqtt_server: str, prop_changed_callback: Callable = None, base_topic: str = '/AC/'):
        self._base_topic: str = base_topic if base_topic[-1] != '/' else base_topic[:-1]
        self._mqtt_client: mqtt.client.Client = mqtt.client.Client()
        self._mqtt_server: str = mqtt_server
        self._prop_changed_callback: Callable = prop_changed_callback

    def mqtt_connect(self):
        self._mqtt_client.on_connect = self._on_mqtt_connect
        self._mqtt_client.on_disconnect = self._on_mqtt_disconnect
        self._mqtt_client.on_message = self._on_mqtt_message
        self._mqtt_client.connect(self._mqtt_server)
        self._mqtt_client.loop_start()

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        for topic in self.get_subscription_list():
            self._mqtt_client.subscribe(topic)

    def _on_mqtt_disconnect(self, client, userdata, flags, rc):
        pass

    def _on_mqtt_message(self, client, userdata, msg):
        logging.info("Data received on topic %s: %s" % (msg.topic, msg.payload))
        topic_splitted = msg.topic.split('/')
        property_id = topic_splitted[-1]
        property = self.get(property_id, None)
        if property is not None:
            property.value = msg.payload.decode('utf-8')
            if self._prop_changed_callback:
                self._prop_changed_callback(property)

    def __setitem__(self, key, value):
        if isinstance(key, SamsungACProperty):
            key = key.samsung_property

        already_exists = True if key in self.keys() else False

        if isinstance(value, SamsungACProperty):
            super(SamsungACPropertyList, self).__setitem__(key, value)
            obj: SamsungACProperty = self[key]
        else:
            obj: SamsungACProperty = self[key]
            obj.value = value

            logging.debug('Publishing %s to topic %s' % (obj.value, self._get_full_topic('Reply', obj)))
            self._mqtt_client.publish(self._get_full_topic('Reply', obj), obj.value)

        if not already_exists and self._mqtt_client.is_connected():
            self._mqtt_client.subscribe(self._get_full_topic(obj))

    def __getitem__(self, item):
        return super(SamsungACPropertyList, self).__getitem__(item)
    
    def __iadd__(self, other: SamsungACProperty):
        self[other.samsung_property] = other
        return self

    def _get_full_topic(self, command, obj: SamsungACProperty):
        return '%s/%s/%s' % (self._base_topic, command, obj.mqtt_name)

    def get_subscription_list(self):
        return [self._get_full_topic('Set', k[1]) for k in self.items()]


class SamsungAC:
    """
    General class to connect to an air conditioner
    """
    convenient_modes = ['Off', 'Quiet', 'Sleep', 'Smart', 'SoftCool', 'TurboMode', 'WindMode1', 'WindMode2',
                        'WindMode3']
    work_modes = ['Auto', 'Cool', 'Dry', 'Wind', 'Heat']
    wind_modes = ['Auto', 'Low', 'Mid', 'High', 'Turbo']

    def __init__(self, ip_address: str, duid, token='', base_topic: str = '/AC/', friendly_name: str = None,
                 mqtt_broker: str = 'mqtt.agalliazzo.com'):
        """
        Default initializer
        :param ip_address: Address of the air conditioner
        :param duid: Device Unique ID (MAC address) of the air conditioner
        :param token: Auth token if already obtained
        :param base_topic: Base topic for publishing data to the MQTT broker
        :param friendly_name: Friendly name of the AC (e.g. DinningRoomAC, RestRoomAC, BedRoomAC). This is added after
        base_topic to complete the topic for the device
        :param mqtt_broker: MQTT broker address (or FQDN) where to publish and subscribe
        """
        # Network interface
        self.IPAddress: str = ip_address
        self.port: int = 2878
        self.socket: socket.socket = None
        self.ssl_socket: SSLSocket = None
        self.ssl_context: SSLContext = None
        self.IsConnected: bool = False
        self.duid: str = duid
        self.token: str = token
        self.friendly_name: str = friendly_name or duid
        base_topic = base_topic if base_topic[:-1] == '/' else base_topic + '/'
        self.properties: SamsungACPropertyList = SamsungACPropertyList(mqtt_broker, self.mqtt_prop_change_request,
                                                base_topic + self.friendly_name)
        self.properties += SamsungACProperty('AC_FUN_ENABLE', 'RW')
        self.properties += SamsungACProperty('AC_FUN_POWER')
        self.properties += SamsungACProperty('AC_FUN_SUPPORTED')
        self.properties += SamsungACProperty('AC_FUN_OPMODE')
        self.properties += SamsungACProperty('AC_FUN_TEMPSET', data_type=int)
        self.properties += SamsungACProperty('AC_FUN_COMODE')
        self.properties += SamsungACProperty('AC_FUN_ERROR')
        self.properties += SamsungACProperty('AC_FUN_TEMPNOW')
        self.properties += SamsungACProperty('AC_FUN_SLEEP')
        self.properties += SamsungACProperty('AC_FUN_WINDLEVEL')
        self.properties += SamsungACProperty('AC_FUN_DIRECTION')
        self.properties += SamsungACProperty('AC_ADD_AUTOCLEAN')
        self.properties += SamsungACProperty('AC_ADD_APMODE_END')
        self.properties += SamsungACProperty('AC_ADD_STARTWPS')
        self.properties += SamsungACProperty('AC_ADD_SPI')
        self.properties += SamsungACProperty('AC_SG_WIFI')
        self.properties += SamsungACProperty('AC_SG_INTERNET')
        self.properties += SamsungACProperty('AC_ADD2_VERSION')
        self.properties += SamsungACProperty('AC_SG_MACHIGH')
        self.properties += SamsungACProperty('AC_SG_MACMID')
        self.properties += SamsungACProperty('AC_SG_MACLOW')
        self.properties += SamsungACProperty('AC_SG_VENDER01')
        self.properties += SamsungACProperty('AC_SG_VENDER02')
        self.properties += SamsungACProperty('AC_SG_VENDER03')
        self.properties.mqtt_connect()
        # Listener
        self.exitThread = Event()
        self.listeningThread = Thread(target=self.listener)
        self.on_token_received: Callable = None

    def mqtt_prop_change_request(self, prop: SamsungACProperty):
        logging.info("%s: MQTT prop change requested for property %s" % (self.friendly_name, prop))
        self._device_control(prop.samsung_property, prop.value)

    def check_resp(self, element, resp):
        if element.attrib['Type'] == resp and element.attrib['Status'] == 'Okay':
            return True
        return False

    def listener(self):
        """
        Listener thread to read socket data
        TODO: Use select to poll the socket, this is blocking and is not beautiful
        :return:
        """
        while not self.exitThread.is_set():
            ready = select.select([self.ssl_socket], [], [], 1)
            if ready[0]:
                data = self.ssl_socket.read(len=2048)
            else:
                continue
            if b'DRC-1.00' in data:
                continue
            logging.debug("%s: Received: %s" % (self.friendly_name, data))
            tree = ElementTree.ElementTree(ElementTree.fromstring(data))
            root = tree.getroot()
            if root.tag == 'Update':
                if root.attrib['Type'] == 'InvalidateAccount':
                    logging.info("%s: Not yet authenticated... proceeding with login..." % self.friendly_name)
                    self.login()
                else:
                    # TODO: Check how to merge in a whole function, something is strange in here about how I wrote this
                    self.parse_update(root)

            if root.tag == 'Response':
                if self.check_resp(root, 'AuthToken'):
                    #login sucessfull
                    self.get_status()

                if self.check_resp(root, 'DeviceState'):
                    self.parse_status(root)

    def parse_update(self, el: xml.etree.ElementTree.Element):
        """
        Process and update command from the air conditioner
        :param el: xml received element
        :return:
        """
        type = el.attrib.get('Type', None)
        if type == 'GetToken':
            token = el.attrib.get('Token')
            logging.info("%s: Token received: %s" % (self.friendly_name, token))
            self.token = token
            if self.on_token_received:
                self.on_token_received(self.duid, token)

        for child in el.find('Status'):
            if child.tag == 'Attr':
                self.properties[child.attrib['ID']] = child.attrib['Value']

    def parse_status(self, el: xml.etree.ElementTree.Element):
        """
        Process a DeviceStatus "command" from the air conditioner
        :param el: xml received element
        :return:
        """
        for child in el.find('DeviceState').find('Device'):
            if child.tag == 'Attr':
                logging.debug(child.attrib['ID'], child.attrib['Value'], child.attrib['Type'])
                self.properties[child.attrib['ID']] = child.attrib['Value']

    def _send(self, data: bytes or str):
        """
        Send data to air conditioner
        :param data: data to be sent
        :return:
        """
        if isinstance(data, str):
            data = str.encode(data)
        logging.info("%s: Sending: %s" % (self.friendly_name, data) )
        try:
            self.ssl_socket.write(data + b"\r\n")
        except (ssl.SSLEOFError, ValueError) as err:
            logging.error("%s: SSL protocol violation (%s), trying to reconnect" % (self.friendly_name, err))
            self.disconnect()
            self.connect()

    def _device_control(self, key, value):
        """
        Execute a change property request on the air conditioner
        :param key: property to change
        :param value: new value
        :return:
        """
        id = random.randint(0, 10000)
        self._send(
            '<Request Type="DeviceControl"><Control CommandID="cmd%s" DUID="%s"><Attr ID="%s" Value="%s" /></Control></Request>' %
            (id, self.duid, key, value)
        )

    def disconnect(self):
        if self.IsConnected:
            try:
                self.ssl_socket.close()
            except SSLError as err:
                logging.warning("%s: Error disconnecting: %s" % (self.friendly_name, err))
        self.IsConnected = False
        self.exitThread.set()

    def connect(self):
        """
        Connect to the air conditioner
        :return:
        """
        if self.IsConnected:
            return

        self.socket = socket.socket(AF_INET, SOCK_STREAM)
        self.ssl_context = SSLContext(protocol=ssl.PROTOCOL_SSLv23)
        self.ssl_context.options &= ~(ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2)
        self.ssl_socket = ssl.wrap_socket(self.socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers='DEFAULT:!DH')
        #TODO: Manage errors better?
        try:
            self.ssl_socket.connect((self.IPAddress, self.port))
            self.exitThread.clear()
            self.listeningThread.start()
            logging.info("%s: Connected to %s" % (self.friendly_name, self.IPAddress))
            self.IsConnected = True
            return
        except (SSLError, TimeoutError, ConnectionResetError) as err:
            logging.error('%s: %s', self.friendly_name, err)
            logging.error('%s: %s', self.friendly_name, traceback.format_exc())

        self.IsConnected = False

    def get_token(self):
        """
        Start the authorization process.
        This mean:
        - Ask to the air conditioner to issue a Token
        - Turn on the air conditioner through the remote controller to confirm the token generation (if AC is on tunr off and on again)
        - On answer from AC self.on_token_received is called with the MAC of the AC and the token received
        :return:
        """
        self.connect()
        self._send(b'<Request Type="GetToken"/>')
        logging.info('%s: Token request sent' % self.friendly_name)

    def login(self):
        """
        Login to the AC using the received token
        :return:
        """
        self._send(b'<Request Type="AuthToken"><User Token="%s" /></Request>' % str.encode(self.token))

    def get_status(self):
        """
        Get the AC current status (list all the properties)
        :return:
        """
        self._send('<Request Type="DeviceState" DUID="%s"></Request>' %  self.duid )

    def turn_on(self):
        """
        Turn on the AC
        :return:
        """
        self._device_control('AC_FUN_POWER', 'On')

    def turn_off(self):
        """
        Turn off the AC
        :return:
        """
        self._device_control('AC_FUN_POWER', 'Off')

    def set_temperature(self, target: int):
        """
        Set the target temperature
        :param target: Target temperature
        :return:
        """
        assert isinstance(target, int)
        self._device_control('AC_FUN_TEMPSET', target)

    def get_temperature(self):
        """
        Get the current temperature setpoint
        :return:
        """
        return self.properties['AC_FUN_TEMPSET']

    def set_windmode(self, mode: int or str):
        """
        Set the fan level
        :param mode:
        :return:
        """
        if isinstance(mode, int):
            mode = self.wind_modes[mode]
        self._device_control('AC_FUN_WINDLEVEL', mode)

    def get_actual_temperature(self):
        """
        Read the actual room temperature
        :return:
        """
        return self.properties['AC_FUN_TEMNOW']


def update_configured_devices(configured_devices: SamsungAirConditionerConfigParser):
    """
    Start a discovery process using SSDP and update the configuration file with the addresses of the air conditioners
    TODO: This process is blocking. Maybe we can use a non-blocking style
    :param configured_devices: instance of SamsungAirConditionerConfigParser
    :return:
    """
    discovery = SamsungDiscovery()
    while not discovery.discovery_finished:
        time.sleep(1)
    for mac, ipaddr in discovery.discovered_items.items():
        device = configured_devices.get(mac, None)
        if device is None:
            device = SamsungAirConditioner(mac_address=mac, ip_address=ipaddr, nickname='', token='')
        configured_devices[mac] = device
    configured_devices.save()


configured_devices = SamsungAirConditionerConfigParser()


def on_token_received(ac, token):
    """
    Callback to update the configured devices once the token is received
    :param ac: MAC address (index of the configuration dict) for the air conditioner
    :param token: Token received
    :return:
    """
    configured_devices[ac].token = token
    configured_devices.save()


def create_interfaces() -> ({str, SamsungAirConditioner}, SamsungAC):
    """
    Create a dictionary of SamsungAC objects from the configured file
    :return: A dictionary of SamsungAC objects and the first element of the dictionary
    """
    acs = {}
    for mac, device in configured_devices.items():
        acs[device.nickname] = SamsungAC(ip_address=device.ip_address, duid=device.mac_address, token=device.token,
                                         base_topic=device.base_topic, friendly_name=device.nickname,
                                         mqtt_broker='mqtt.agalliazzo.com')
        acs[device.nickname].on_token_received = on_token_received

    return acs, next(iter(acs.items()))[1]


def interactive():
    """
    Interactive shell to run configuration stuff and testing
    :return:
    """
    logging.info('Total device in conf file: %s' % len(configured_devices))

    acs, ac = create_interfaces()

    r = ''
    while r != 'q':
        print('s: Select AC')
        print('d: Start discovery of ACs')
        print('1: Connect')
        print('2: Turn off')
        print('3: Turn on')
        print('4: get status')
        print('5: get token')
        print('6: set temperature')
        print('7: set fan')
        print('q: Exit')
        r = input('Choose the command: ')
        if r == 's':
            pprint('Available ACs: %s' % acs.keys())
            ac_name = ''
            while ac_name not in acs.keys():
                ac_name = input('Select: ')
            ac = acs[ac_name]
        if r == 'd':
            update_configured_devices(configured_devices)
            acs, ac = create_interfaces()
        if r == '1':
            ac.connect()
            logging.info("Connected")
        if r == '2':
            ac.turn_off()
        if r == '3':
            ac.turn_on()
        if r == '4':
            ac.get_status()
        if r == '5':
            ac.get_token()
        if r == '6':
            r = input('Which temperature? ')
            ac.set_temperature(int(r))

        if r == '7':
            r = input('Which fan (%s)? ' % SamsungAC.wind_modes)
            ac.set_windmode(r)


exit_ac_threads = Event()


def ac_worker_thread(ac: SamsungAC):
    thread_state: int = 0
    while not exit_ac_threads.is_set():
        match thread_state:
            case 0:
                logging.info("Connecting to AC %s" % ac.friendly_name)
                ac.connect()
                thread_state += 1
            case 1:
                if not ac.IsConnected:
                    logging.error("Fail to connect to AC %s", ac.friendly_name)
                    logging.info("Retrying connection in 5s")
                    time.sleep(5)
                    thread_state = 0
                    continue
                thread_state += 1
            case 2:
                time.sleep(5)


def automatic_run():
    """
    Automatically start the system, connect to the air conditioner and start mqtt client
    :return:
    """
    #print('Total device in conf file: %s' % len(configured_devices))

    acs, _ = create_interfaces()

    for friendly_name, ac in acs.items():
        t = Thread(target=ac_worker_thread, args=[ac])
        t.start()


if __name__ == '__main__':
    if '-i' in sys.argv:
        interactive()
    else:
        automatic_run()


    #parser = argparse.ArgumentParser(description='Samsung AC old mqtt interface (based on port 2787)')
    #parser.add_argument('-i', dest='')

