import os
from multiprocessing import Queue, Process
from typing import ClassVar
from unittest import TestCase

from fido2.ctap2 import Ctap2
from fido2.pcsc import CtapPcscDevice


class CTAPTestCase(TestCase):

    q: ClassVar[Queue]
    p: ClassVar[Process]
    device: CtapPcscDevice
    ctap2: Ctap2

    DEBUG_PORT = 5005
    SUSPEND_ON_LAUNCH = False
    VIRTUAL_DEVICE_NAME = "Virtual PCD"

    @classmethod
    def start_jvm(cls):
        import jpype.imports

        my_path = os.path.dirname(os.path.dirname(__file__))
        path_to_jars = os.path.join(my_path, 'build', 'libs')
        jars = os.listdir(path_to_jars)
        main_jars = []
        test_jars = []
        for jar in jars:
            if jar.startswith('fido2applet-tests-'):
                test_jars.append(jar)
            elif jar.startswith('fido2applet-'):
                main_jars.append(jar)
        if len(main_jars) == 0:
            raise ValueError("Applet not built - run ./gradlew jar")
        elif len(main_jars) > 1:
            raise ValueError("More than one main jar in build/libs - remove all but one")
        if len(test_jars) == 0:
            raise ValueError("Tests not built - run ./gradlew testJar")
        elif len(test_jars) > 1:
            raise ValueError("More than one test jar in build/libs - remove all but one")

        jc_home = os.environ.get("JC_HOME")
        if not jc_home:
            raise ValueError("$JC_HOME must be set to the path of your JavacardKit")
        jc_jars = os.path.join(jc_home, 'lib')

        classpath = [
            os.path.abspath(os.path.join(path_to_jars, main_jars[0])),  # Applet jar
            os.path.abspath(os.path.join(path_to_jars, test_jars[0])),  # Test support jar
        ]
        classpath += [
            os.path.join(jc_jars, x) for x in os.listdir(jc_jars)
        ]

        suspend_char = 'y' if cls.SUSPEND_ON_LAUNCH else 'n'

        jpype.startJVM(
            "-agentlib:jdwp=transport=dt_socket,server=y,"
            f"suspend={suspend_char},address={cls.DEBUG_PORT}",
            classpath=classpath
        )

    @classmethod
    def launch_sim(cls, q: Queue):
        cls.start_jvm()
        from us.q3q.fido2 import VSim

        sim = VSim.startBackgroundSimulator()
        VSim.installApplet(sim)
        q.put(None, block=True)
        while True:
            should_shut_down = q.get(block=True)
            if should_shut_down:
                # We're done - exit
                break
            # Reset the simulator to fresh
            sim.resetRuntime()
            VSim.installApplet(sim)
            q.put(None, block=True)

    @classmethod
    def setUpClass(cls) -> None:
        cls.q = Queue()
        cls.p = Process(target=cls.launch_sim, args=(cls.q,))
        cls.p.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.p.kill()
        cls.p.join()

    def setUp(self) -> None:
        self.q.get(block=True)  # Wait for applet to be started in JVM

        devs = list(CtapPcscDevice.list_devices(self.VIRTUAL_DEVICE_NAME))
        assert 1 == len(devs)
        self.device = devs[0]
        self.ctap2 = Ctap2(self.device)

    def tearDown(self) -> None:
        self.q.put(False)  # Tell JVM to reset applet state
