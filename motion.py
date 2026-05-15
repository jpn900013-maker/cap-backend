import numpy as np
import string
import random
import zlib
import math
import time
import re


class Utils:
    @staticmethod
    def randint(a: int, b: int) -> int:
        return random.randint(min(a, b), max(a, b))

    @staticmethod
    def get_ms() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def movements(start: tuple, goal: tuple, screen: tuple, max_points: int, rnd: int, polling: int) -> tuple:
        """Generate realistic Bézier-curve mouse movement with velocity profile and jitter.
        Returns (mouse_movement, pointer_mouse_movement) as separate arrays."""
        start = (int(start[0]), int(start[1]))
        goal = (int(goal[0]), int(goal[1]))
        screen = (int(screen[0]), int(screen[1]))

        # Build control points for a cubic Bézier
        cp = 4
        control = [start]
        for _ in range(cp - 2):
            rnd_x = Utils.randint(-rnd, rnd)
            rnd_y = Utils.randint(-rnd, rnd)
            int_point = (
                Utils.randint(min(start[0], goal[0]), max(start[0], goal[0])) + rnd_x,
                Utils.randint(min(start[1], goal[1]), max(start[1], goal[1])) + rnd_y,
            )
            clamped = (
                int(np.clip(int_point[0], 0, screen[0])),
                int(np.clip(int_point[1], 0, screen[1])),
            )
            control.append(clamped)
        control.append(goal)

        # Manual Bézier evaluation (no external bezier lib needed)
        distance = Utils.distance(start, goal)
        num_steps = min(max_points, max(16, int(distance / polling)))

        # Bell-curve velocity profile (Gaussian)
        t_lin = np.linspace(-3, 3, num_steps)
        velocity = np.exp(-(t_lin ** 2))
        velocity /= np.sum(velocity)
        u = np.cumsum(velocity)
        u /= u[-1]

        # Evaluate cubic Bézier at each u position
        n = len(control) - 1
        points_x = np.zeros(num_steps)
        points_y = np.zeros(num_steps)
        for i, pt in enumerate(control):
            coeff = np.array([math.comb(n, i) * (ui ** i) * ((1 - ui) ** (n - i)) for ui in u])
            points_x += coeff * pt[0]
            points_y += coeff * pt[1]

        # Add micro-jitter proportional to movement speed
        motion = []
        pointer_mouse = []
        ts = 0
        base_ts = Utils.get_ms()
        prev_x, prev_y = start

        for x_val, y_val in zip(points_x.astype(int), points_y.astype(int)):
            delta_x = abs(int(x_val) - prev_x)
            delta_y = abs(int(y_val) - prev_y)
            max_delta = max(delta_x, delta_y)
            jitter_range = min(2, max(1, max_delta // 10))
            jitter_x = Utils.randint(-jitter_range, jitter_range)
            jitter_y = Utils.randint(-jitter_range, jitter_range)
            jittered_x = int(np.clip(int(x_val) + jitter_x, 0, screen[0]))
            jittered_y = int(np.clip(int(y_val) + jitter_y, 0, screen[1]))

            # Simulate realistic polling interval (no real sleep)
            incre = int(np.random.normal(loc=30, scale=10))
            incre = max(10, incre)
            timestamp = base_ts + ts

            motion.append([jittered_x, jittered_y, timestamp])
            pointer_mouse.append([jittered_x, jittered_y, timestamp])

            ts += incre
            prev_x, prev_y = int(x_val), int(y_val)

        return motion, pointer_mouse

    @staticmethod
    def check_mm(start: tuple, goal: tuple, screen_width: int, screen_height: int) -> list:
        """Advanced mouse movement for challenge interaction with acceleration/deceleration."""
        start = (int(start[0]), int(start[1]))
        goal = (int(goal[0]), int(goal[1]))
        distance = math.hypot(goal[0] - start[0], goal[1] - start[1])
        peak_vel = 22000 + 0.2 * distance
        avg_speed = peak_vel / 4
        num_points = max(random.randint(16, 20), int(distance / (avg_speed / 65)))
        total_time = max(distance / avg_speed, 0.01)
        timestamp = int(time.time() * 1000)
        t = np.linspace(0, total_time, num_points)
        accel_time = total_time * 0.25

        velocity = (
            np.where(t <= accel_time, peak_vel * (t / max(accel_time, 0.001)) ** 2, 0) +
            np.where(t > accel_time, peak_vel * ((1 - (t - accel_time) / max(total_time - accel_time, 0.001)) ** 3), 0)
        )
        velocity = np.clip(velocity, 0, None)
        position = np.cumsum(velocity)
        if position[-1] > 0:
            position /= position[-1]

        control = [
            (min(max(start[0] + random.uniform(0.3, 0.8) * (goal[0] - start[0]) + random.uniform(-70, 70), 0), screen_width),
             min(max(start[1] + random.uniform(0.3, 0.8) * (goal[1] - start[1]) + random.uniform(-70, 70), 0), screen_height))
            for _ in range(3)
        ]
        points = [start] + control + [goal]

        def curve(t_val, pts):
            n = len(pts) - 1
            return sum(
                math.comb(n, i) * (t_val ** i) * ((1 - t_val) ** (n - i)) * (np.array(pt) + np.random.normal(0, 0.3, size=len(pt)))
                for i, pt in enumerate(pts)
            )

        positions = np.array([curve(s, points) for s in position])
        deviation = distance * 0.003
        positions += np.random.uniform(-deviation, deviation, (num_points, 2))
        tremors = distance * 0.005 * np.sin(2 * np.pi * random.uniform(1.5, 3.5) * t[:, None])
        positions += tremors
        strength = distance * 0.01
        jitter = np.random.uniform(-strength, strength, positions.shape)
        positions += jitter

        positions = np.round(positions).astype(int)
        positions[0], positions[-1] = start, goal
        positions = np.clip(positions, [0, 0], [screen_width, screen_height])
        stamps = [timestamp + int(ti * 1000) for ti in t]

        return [[int(positions[i][0]), int(positions[i][1]), int(stamps[i])] for i in range(num_points)]

    @staticmethod
    def theme(theme_name: str) -> int:
        return zlib.crc32(theme_name.encode()) & 0xFFFFFFFF

    @staticmethod
    def distance(a: tuple, b: tuple) -> float:
        return math.sqrt((b[0] - a[0]) ** 2 + (b[1] - a[1]) ** 2)

    @staticmethod
    def mean_periods(timestamps: list) -> float:
        periods = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        return sum(periods) / len(periods) if periods else 0

    @staticmethod
    def random_point(bbox: tuple) -> tuple:
        return Utils.randint(int(bbox[0][0]), int(bbox[1][0])), Utils.randint(int(bbox[0][1]), int(bbox[1][1]))

    @staticmethod
    def get_center(bbox: tuple) -> tuple:
        x1, y1 = int(bbox[0][0]), int(bbox[0][1])
        x2, y2 = int(bbox[1][0]), int(bbox[1][1])
        return int(x1 + (x2 - x1) / 2), int(y1 + (y2 - y1) / 2)

    @staticmethod
    def random_middle(bbox: tuple) -> tuple:
        mx, my = (sum(c) / 2 for c in zip(*bbox))
        wr, hr = ((e - s) * 0.1 for s, e in zip(*bbox))
        return (random.uniform(mx - wr, mx + wr), random.uniform(my - hr, my + hr))


class rectangle:
    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height

    def get_size(self) -> tuple:
        return self.width, self.height

    def get_box(self, rel_x: int, rel_y: int) -> tuple:
        rel_x, rel_y = int(rel_x), int(rel_y)
        return (rel_x, rel_y), (rel_x + self.width, rel_y + self.height)

    def get_corners(self, rel_x: int = 0, rel_y: int = 0) -> list:
        rel_x, rel_y = int(rel_x), int(rel_y)
        return [
            (rel_x, rel_y),
            (rel_x + self.width, rel_y),
            (rel_x, rel_y + self.height),
            (rel_x + self.width, rel_y + self.height),
        ]


class Widget:
    def __init__(self, rel_position: tuple) -> None:
        self.widget = rectangle(300, 75)
        self.check_box = rectangle(28, 28)
        self.rel_position = rel_position

    def get_check(self) -> tuple:
        return self.check_box.get_box(16 + self.rel_position[0], 23 + self.rel_position[1])

    def get_closest(self, position: tuple) -> tuple:
        corners = self.widget.get_corners(self.rel_position[0], self.rel_position[1])
        sorted_corners = sorted(corners, key=lambda c: Utils.distance(position, c))
        return sorted_corners[0], sorted_corners[1]


class text_challenge:
    def __init__(self, box_centre: tuple, screen_size: tuple) -> None:
        x = min(max(box_centre[0] + 25, 0), screen_size[0] / 2 - 185)
        y = min(max(box_centre[1] - 150, 10), screen_size[1] - 310)
        self.widget_position = (int(x), int(y))
        self.widget = rectangle(370, 300)
        self.text_box = rectangle(314, 40)
        self.button = rectangle(80, 35)

    def get_text_box(self) -> tuple:
        return self.text_box.get_box(28, 165)

    def get_button_box(self) -> tuple:
        return self.button.get_box(280, 255)

    def get_closest(self, position: tuple) -> tuple:
        corners = self.widget.get_corners(self.widget_position[0], self.widget_position[1])
        sorted_corners = sorted(corners, key=lambda c: Utils.distance(position, c))
        return sorted_corners[0], sorted_corners[1]


COMMON_SCREEN_SIZES = [
    (1280, 720), (1280, 800), (1366, 768), (1440, 900),
    (1600, 900), (1680, 1050), (1920, 1080), (1920, 1200),
    (2560, 1440),
]

COMMON_CORE_MEMORY = [
    (2, 4), (4, 4), (4, 8), (6, 12), (8, 16), (16, 32),
]


def _extract_chrome_ver(ua: str) -> str:
    m = re.search(r'Chrome/(\d+)', ua)
    return m.group(1) if m else "120"


def _extract_platform(ua: str) -> str:
    if 'Macintosh' in ua or 'Mac OS X' in ua:
        return 'macOS'
    elif 'Linux' in ua:
        return 'Linux'
    return 'Windows'


def _extract_platform_nav(ua: str) -> str:
    if 'Macintosh' in ua or 'Mac OS X' in ua:
        return 'MacIntel'
    elif 'Linux' in ua:
        return 'Linux x86_64'
    return 'Win32'


class get_cap:
    def __init__(self, user_agent: str, href: str) -> None:
        self.user_agent = user_agent
        chrome_ver = _extract_chrome_ver(user_agent)
        chrome_full = f"{chrome_ver}.0.0.0"
        platform = _extract_platform(user_agent)
        platform_nav = _extract_platform_nav(user_agent)

        screen_size = random.choice(COMMON_SCREEN_SIZES)
        self.screen_size = screen_size
        cores, memory = random.choice(COMMON_CORE_MEMORY)

        widget_id = '0' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        random_point = Utils.random_point(((0, 0), (screen_size[0] - 150, screen_size[1] - 38)))
        self.widget = Widget(random_point)
        self.position = Utils.random_point(((0, 0), screen_size))

        data = {
            'st': Utils.get_ms(),
            'pm': [],
            'pm-mp': 0,
            'mm': [],
            'mm-mp': 0,
            'md': [],
            'md-mp': 0,
            'mu': [],
            'mu-mp': 0,
            'v': 1,
            'topLevel': self._top_level(screen_size, cores, memory, chrome_ver, chrome_full, platform, platform_nav),
            'session': [],
            'widgetList': [widget_id],
            'widgetId': widget_id,
            'href': href,
            'prev': {
                'escaped': False,
                'passed': False,
                'expiredChallenge': False,
                'expiredResponse': False,
            },
        }

        goal = Utils.random_point(self.widget.get_check())
        self.mouse_movement, self.pointer_mouse_movement = Utils.movements(
            self.position, goal, self.screen_size, 20, 5, 10
        )
        data['pm'] = [[x - random_point[0], y - random_point[1], t] for x, y, t in self.pointer_mouse_movement]
        data['pm-mp'] = Utils.mean_periods([x[-1] for x in self.pointer_mouse_movement])
        data['mm'] = [[x - random_point[0], y - random_point[1], t] for x, y, t in self.mouse_movement]
        data['mm-mp'] = Utils.mean_periods([x[-1] for x in self.mouse_movement])
        data['md'].append(data['mm'][-1][:-1] + [Utils.get_ms()])
        data['mu'].append(data['mm'][-1][:-1] + [Utils.get_ms() + Utils.randint(50, 150)])
        self.data = data

    def _top_level(self, screen_size, cores, memory, chrome_ver, chrome_full, platform, platform_nav):
        data = {
            'st': Utils.get_ms(),
            'sc': {
                'availWidth': screen_size[0],
                'availHeight': screen_size[1] - 40,
                'width': screen_size[0],
                'height': screen_size[1],
                'colorDepth': 24,
                'pixelDepth': 24,
                'availLeft': 0,
                'availTop': 0,
                'onchange': None,
                'isExtended': False,
            },
            'wi': [screen_size[0], screen_size[1] - 87],
            'nv': {
                'vendorSub': '',
                'productSub': '20030107',
                'vendor': 'Google Inc.',
                'maxTouchPoints': 0,
                'scheduling': {},
                'userActivation': {},
                'doNotTrack': '1',
                'geolocation': {},
                'connection': {},
                'pdfViewerEnabled': True,
                'webkitTemporaryStorage': {},
                'windowControlsOverlay': {},
                'hardwareConcurrency': cores,
                'cookieEnabled': True,
                'appCodeName': 'Mozilla',
                'appName': 'Netscape',
                'appVersion': self.user_agent.split('Mozilla/')[1] if 'Mozilla/' in self.user_agent else '5.0',
                'platform': platform_nav,
                'product': 'Gecko',
                'userAgent': self.user_agent,
                'language': 'en-US',
                'languages': ['en-US', 'en'],
                'onLine': True,
                'webdriver': False,
                'deprecatedRunAdAuctionEnforcesKAnonymity': False,
                'protectedAudience': {},
                'bluetooth': {},
                'storageBuckets': {},
                'clipboard': {},
                'credentials': {},
                'keyboard': {},
                'managed': {},
                'mediaDevices': {},
                'storage': {},
                'serviceWorker': {},
                'virtualKeyboard': {},
                'wakeLock': {},
                'deviceMemory': memory,
                'userAgentData': {
                    'brands': [
                        {'brand': 'Google Chrome', 'version': chrome_full},
                        {'brand': 'Chromium', 'version': chrome_full},
                        {'brand': 'Not_A Brand', 'version': '24'},
                    ],
                    'mobile': False,
                    'platform': platform,
                },
                'login': {},
                'ink': {},
                'mediaCapabilities': {},
                'hid': {},
                'locks': {},
                'gpu': {},
                'mediaSession': {},
                'permissions': {},
                'presentation': {},
                'usb': {},
                'xr': {},
                'serial': {},
                'plugins': [
                    'internal-pdf-viewer',
                    'internal-pdf-viewer',
                    'internal-pdf-viewer',
                    'internal-pdf-viewer',
                    'internal-pdf-viewer',
                ],
            },
            'dr': '',
            'inv': False,
            'exec': 'm',
            'wn': [[screen_size[0], screen_size[1], 1, Utils.get_ms()]],
            'wn-mp': 0,
            'xy': [[0, 0, 1, Utils.get_ms()]],
            'xy-mp': 0,
            'pm': [],
            'pm-mp': 0,
            'mm': [],
            'mm-mp': 0,
        }

        position = (int(self.position[0]), int(self.position[1]))
        goal = Utils.random_point(self.widget.get_closest(position))
        mouse_movement, pointer_mouse_movement = Utils.movements(
            position, goal, self.screen_size, 75, 5, 15
        )
        self.position = goal
        data['pm'] = pointer_mouse_movement
        data['pm-mp'] = Utils.mean_periods([x[-1] for x in pointer_mouse_movement])
        data['mm'] = mouse_movement
        data['mm-mp'] = Utils.mean_periods([x[-1] for x in mouse_movement])

        return data


class check_cap:
    def __init__(self, old_data) -> None:
        self.old_data = old_data
        self.screen_size = old_data.screen_size
        challenge_center = Utils.get_center(old_data.widget.get_check())
        self.challenge = text_challenge(challenge_center, self.screen_size)
        position = (int(self.challenge.widget_position[0]), int(self.challenge.widget_position[1]))

        top = old_data.data['topLevel']
        top['lpt'] = Utils.get_ms() + random.randint(10000, 13000)

        self.data = {
            'st': Utils.get_ms(),
            'dct': Utils.get_ms(),
            'pm': [],
            'pm-mp': 0,
            'mm': [],
            'mm-mp': 0,
            'md': [],
            'md-mp': 0,
            'mu': [],
            'mu-mp': 0,
            'v': 1,
            'topLevel': top,
        }

        for _ in range(3):
            # Move to text box
            goal = Utils.random_middle(self.challenge.get_text_box())
            mm = Utils.check_mm(position, goal, self.screen_size[0], self.screen_size[1])
            self.data['mm'].extend(mm)
            self.data['pm'].extend(mm)
            self.data['md'].append(list(goal) + [Utils.get_ms()])
            self.data['mu'].append(list(goal) + [Utils.get_ms() + 100])
            position = goal

            # Move to button
            goal = Utils.random_point(self.challenge.get_button_box())
            mm = Utils.check_mm(position, goal, self.screen_size[0], self.screen_size[1])
            self.data['mm'] += mm
            self.data['pm'] += mm
            self.data['md'].append(list(goal) + [Utils.get_ms()])
            self.data['mu'].append(list(goal) + [Utils.get_ms() + 100])
            position = goal

        # Compute mean periods
        for key in ['mm', 'md', 'mu', 'pm']:
            self.data[key + '-mp'] = Utils.mean_periods([pt[-1] for pt in self.data[key]])


class motion_data:
    """Drop-in replacement for the old motion_data class."""
    def __init__(self, user_agent: str, url: str) -> None:
        self.user_agent = user_agent
        self.url = url
        self.get_captcha_motion_data = get_cap(self.user_agent, self.url)

    def get_captcha(self) -> dict:
        return self.get_captcha_motion_data.data

    def check_captcha(self) -> dict:
        return check_cap(self.get_captcha_motion_data).data
