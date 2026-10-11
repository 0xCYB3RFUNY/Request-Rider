#!/usr/bin/env python3
"""Тести пониження прав у `start.sh`.

Скрипт запускали через `sudo ./start.sh`, і це ламало стенд: venv,
`data/` і кеш браузерів створювалися від root, а сам Firefox під root
не піднімався. Цей файл перевіряє функції, які виправляють саме це:
`resolve_stack_user`, `reclaim_root_owned_paths` і `drop_root_privileges`.

Тести не створюють нічого поза `$TMPDIR` і не торкаються реальних
каталогів репозиторію: `ROOT_DIR`, `DATA_DIR`, `VENV_DIR`,
`WORKER_VENV_DIR` і `BIN_DIR` підмінюються на тимчасові.

Запуск (див. AGENTS.md, «Команды проверки» — поруч з `manage.py test`):

    python3 tools/test_start_privilege_drop.py
"""

from __future__ import annotations

import os
import pwd
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
START_SH = REPO_ROOT / "start.sh"

# Імена функцій, які витягуються з `start.sh` для перевірки. Тому сам
# `start.sh` не виконується: він піднімає стенд, а тут потрібні лише
# три функції, і їхня логіка не залежить від решти файла.
GUARD_FUNCTIONS = (
    "resolve_stack_user",
    "reclaim_root_owned_paths",
    "drop_root_privileges",
)


def _own_tmp_base() -> str:
    """Каталог, який належить поточному користувачу, для `mkdtemp`.

    `TMPDIR` зазвичай `/tmp` — він належить root. Створювати «репозиторій»
    там означало б, що в нього немає власника, і перевірка падала б на
    своїй підготовці. Підбираємо базу, яка реально належить цьому
    користувачу: спершу `HOME`, потім каталог поруч із `start.sh` — там
    репозиторій гарантовано має правильного власника.
    """
    for candidate in (Path.home(), REPO_ROOT):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / f".rr-privdrop-probe-{os.getpid()}"
            probe.mkdir(exist_ok=True)
            probe.rmdir()
            return str(candidate)
        except OSError:
            continue
    raise unittest.SkipTest("немає каталогу, доступного цьому користувачу")


def read_start_sh() -> str:
    if not START_SH.is_file():
        raise unittest.SkipTest(f"немає {START_SH}")
    return START_SH.read_text(encoding="utf-8")


def extract_function(source: str, name: str) -> str:
    """Вирізати тіло функції з bash-исходника.

    Рахуємо дужки, а не шукаємо перший `}` на своєй лінії: вкладений
    `case`/`if` має власні дужки, і перший такий `}` обрвав би функцію
    на півдорозі — тест перевіряв би обрізану версію, а не ту, що в
    файлі.
    """
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"функція {name}() не знайдена в {START_SH.name}")

    start = match.start()
    depth = 0
    for index in range(match.end() - 1, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]

    raise AssertionError(f"тіло функції {name}() не закрито")


class PrivilegeDropTestCase(unittest.TestCase):
    """Спільна підготовка: тимчасовий «репозиторій» і витягнуті функції."""

    def setUp(self) -> None:
        self.source = read_start_sh()

        # «Репозиторій» і всі каталоги, які скрипт створює, — у тимчасовому
        # каталозі. Реальний `data/` репозиторію не чіпаємо ні одним тестом.
        #
        # `mkdtemp` без `dir` створює каталог у `$TMPDIR`, а на Linux це
        # зазвичай `/tmp`, який належить root. Такий «репозиторій» власника
        # не має взагалі, і `resolve_stack_user` зрозуміло відмовляє
        # понижувати права — тест падав би на власній підготовці, а не на
        # логіці. Тому каталог створюється там, де він належить цьому
        # користувачу: `stat -c %U` повертає саме його, як на живому
        # репозиторії.
        self.tmp = Path(tempfile.mkdtemp(prefix="rr-privdrop-", dir=_own_tmp_base()))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.data_dir = self.repo / "data"
        self.data_dir.mkdir()
        self.venv_dir = self.repo / "web" / ".venv"
        self.venv_dir.mkdir(parents=True)
        self.worker_venv_dir = self.repo / "browser-worker" / ".venv"
        self.worker_venv_dir.mkdir(parents=True)
        self.bin_dir = self.repo / "bin"
        self.bin_dir.mkdir()

        self.functions = "\n\n".join(
            extract_function(self.source, name) for name in GUARD_FUNCTIONS
        )

    def run_guard(
        self,
        script: str,
        *,
        uid: int,
        sudo_user: str | None = None,
        env: dict[str, str] | None = None,
        tmp_home: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Виконати тіло guard-у в окремому bash-процесі.

        `id -u` підмінено через `fake_id`, а не через реальний uid: тест
        має перевірити гілку «ми root» на машині, де тест запущений
        звичайним користувачем, і єдиний спосіб зробити це —
        підмінити `id`.
        """
        home = tmp_home or (self.tmp / "home")
        home.mkdir(exist_ok=True)

        bindir = self.tmp / "bin"
        bindir.mkdir(exist_ok=True)

        # `id` віддає заданий uid для `-u`/`-un`, і реальну відповідь
        # для всього іншого (`id -u <користувач>` має лишатися справжнім,
        # бо `resolve_stack_user` перевіряє існування користувача саме ним).
        fake_id = bindir / "id"
        fake_id.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-u" ] && [ "$#" -eq 1 ]; then\n'
            f"  echo {uid}\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = "-un" ] && [ "$#" -eq 1 ]; then\n'
            '  echo "root"\n'
            "  exit 0\n"
            "fi\n"
            f"exec /usr/bin/id \"$@\"\n",
            encoding="utf-8",
        )
        fake_id.chmod(0o755)

        # `die` у скрипті друкує в stderr і робить `exit 1`;guard-и
        # викликають його при відсутності користувача, тож заглушка має
        # повторювати саме цю поведінку.
        preamble = (
            "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
            "info() { printf '%s\\n' \"$*\"; }\n"
            "warn() { printf '%s\\n' \"$*\"; }\n"
            'ROOT_DIR="$ROOT_DIR"\n'
            'DATA_DIR="$DATA_DIR"\n'
            'VENV_DIR="$VENV_DIR"\n'
            'WORKER_VENV_DIR="$WORKER_VENV_DIR"\n'
            'BIN_DIR="$BIN_DIR"\n'
            # `SELF_PATH` обчислюється на верхньому рівні `start.sh`, а
            # гармонизатор підставляє лише три функції, тож змінну треба
            # задати тут: інакше `set -u` уронив би `drop_root_privileges`
            # на розіменні, тобто тест падав би на відсутності змінної,
            # а не перевіряв би поведінку.
            'SELF_PATH="$SELF_PATH"\n'
        )

        full_env = dict(os.environ)
        full_env.update(
            {
                "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                "HOME": str(home),
                "ROOT_DIR": str(self.repo),
                "DATA_DIR": str(self.data_dir),
                "VENV_DIR": str(self.venv_dir),
                "WORKER_VENV_DIR": str(self.worker_venv_dir),
                "BIN_DIR": str(self.bin_dir),
                "SELF_PATH": str(START_SH),
            }
        )
        if sudo_user is not None:
            full_env["SUDO_USER"] = sudo_user
        else:
            full_env.pop("SUDO_USER", None)
        if env:
            full_env.update(env)

        return subprocess.run(
            ["bash", "-c", preamble + self.functions + "\n" + script],
            capture_output=True,
            text=True,
            timeout=60,
            env=full_env,
            cwd=str(self.repo),
        )


class TestFunctionsExist(PrivilegeDropTestCase):
    def test_guard_functions_are_present_in_start_sh(self) -> None:
        # `re.MULTILINE` обовʼязковий: без нього `^` читається як «початок
        # файлу», а функції живуть у середині, і перевірка падала б на
        # власному регулярному виразі, а не на відсутньому коді.
        for name in GUARD_FUNCTIONS:
            with self.subTest(function=name):
                found = re.search(
                    rf"^{re.escape(name)}\(\)\s*\{{", self.source, re.MULTILINE
                )
                self.assertIsNotNone(
                    found,
                    f"{name}() відсутня у start.sh — guard не буде викликаний",
                )

    def test_privilege_drop_is_invoked_at_top_level(self) -> None:
        """Гвард має викликатися на верхньому рівні, до першого запису на диск.

        Якщо виклик стояв би лише всередині `ensure_*`, то до нього вже
        створюються `web/.venv` і `data/` — права поверталися б надто
        пізно, і перший запуск від root лишив би root-файли.
        """
        # Крок запускається через обёртку `run_startup_privilege_guard`,
        # тому шукаємо саме її виклик. Пошук лише за `^drop_root_privileges`
        # збігався б і з визначенням `drop_root_privileges() {` — тобто
        # тест був зелений навіть з вилученим викликом, а це «тест, який
        # не може впасти». `\"$@\"` — частина виклику: визначення
        # функції її не містить.
        match = re.search(
            r'^run_startup_privilege_guard\s+"\$@"', self.source, re.MULTILINE
        )
        self.assertIsNotNone(
            match,
            'run_startup_privilege_guard() не викликається з аргументами — '
            "guard не спрацює ніколи",
        )

        # Обёртка має викликати обидві перевірки. Порожня обёртка —
        # це визначення без роботи: guard «є» у файлі й нічого не робить.
        wrapper = extract_function(self.source, "run_startup_privilege_guard")
        self.assertIn(
            'drop_root_privileges "$@"',
            wrapper,
            "обёртка не викликає drop_root_privileges — права не буде знижено",
        )
        self.assertIn(
            "check_no_root_owned_leftovers",
            wrapper,
            "обёртка не перевіряє root-файли — зламаний стенд дасть "
            "Permission denied замість підказки",
        )

        # Перший запис на диск — генерація `data/run/broker_key`. Гвард
        # мусить стояти перед ним: інакше звичайний запуск на зламаному
        # стенді впаде на `mkdir` з помилкою системи, а не з підказкою
        # скрипта. Виміряно 2026-10-11.
        first_write = self.source.find('mkdir -p "$(dirname "$_broker_key_file")"')
        self.assertNotEqual(
            first_write, -1, "у start.sh немає генерації data/run/broker_key"
        )
        self.assertLess(
            match.start(),
            first_write,
            "гвард викликається після першого запису на диск — оператор "
            "побачить Permission denied замість підказки",
        )

        # Перше створення venv — другий marker: після нього `data/`
        # і `web/.venv` уже могли б з'явитися від root.
        first_venv = self.source.find("-m venv")
        self.assertNotEqual(first_venv, -1, "у start.sh немає створення venv")
        self.assertLess(
            match.start(),
            first_venv,
            "гвард викликається після створення venv",
        )


class TestResolveStackUser(PrivilegeDropTestCase):
    def test_uses_sudo_user_when_present(self) -> None:
        current = subprocess.run(
            ["id", "-un"], capture_output=True, text=True, check=True
        ).stdout.strip()

        result = self.run_guard(
            "resolve_stack_user",
            uid=0,
            sudo_user=current,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), current)

    def test_falls_back_to_repo_owner_without_sudo_user(self) -> None:
        """Без `SUDO_USER` стенд має жити від власника репозиторію.

        Порівнюємо саме ІМ'Я користувача, а не uid: `resolve_stack_user`
        повертає ім'я, бо саме ім'я потрібне `setpriv`, і саме воно
        потрапляє в `HOME`-повідомлення оператору.
        """
        owner = pwd.getpwuid(os.getuid()).pw_name

        result = self.run_guard("resolve_stack_user", uid=0)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), owner)

    def test_sudo_user_equal_to_current_user_falls_back_to_owner(self) -> None:
        """`sudo`, викликаний самим root, — не привід лишатися root.

        Саме тут `SUDO_USER=root` і не означає «користувач root»: коли
        сесію вже мав root, єдична людина, для якої стенд має сенс, —
        власник репозиторію. Відмовитися тут означало б змусити
        оператора запускати `sudo su` вручну перед кожним стартом.
        """
        owner = pwd.getpwuid(os.getuid()).pw_name

        result = self.run_guard("resolve_stack_user", uid=0, sudo_user="root")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), owner)

    def test_rejects_root_owned_repository(self) -> None:
        """Єдиний справжній випадок відмови: власник репозиторію — теж root.

        Тоді знизити права нема до кого: стенд у такому каталозі не має
        звичайного користувача, і правильна відповідь — зупинитися з
        поясненням, а не мовчки працювати далі від root.
        """
        result = self.run_guard(
            "resolve_stack_user",
            uid=0,
            # `/` належить root на будь-якій машині, тож це відмова
            # без підготовки root-файлів.
            env={"ROOT_DIR": "/"},
            sudo_user="root",
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), "")

    def test_rejects_nonexistent_sudo_user(self) -> None:
        result = self.run_guard(
            "resolve_stack_user",
            uid=0,
            sudo_user="rr-nonexistent-user-9182734",
        )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), "")


class TestReclaimRootOwnedPaths(PrivilegeDropTestCase):
    def test_non_root_paths_are_left_alone(self) -> None:
        """Guard не торкається файлів, які й так належать користувачу.

        `chown` на власний каталог не змінив би нічого, але виклик
        означав би, що скрипт переписує права на файли, які не його.
        """

        def script() -> str:
            return "reclaim_root_owned_paths \"$(id -un)\"; echo DONE"

        result = self.run_guard(script(), uid=int(os.getuid()))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DONE", result.stdout)
        self.assertNotIn("права повернуто", result.stdout)

    def test_missing_paths_do_not_break_the_guard(self) -> None:
        """Каталогу, якого немає, — не привід зупиняти запуск.

        Перший запуск створює `data/` і `bin/`; як би guard вимагав їх
        наявності, він упав би саме там, де нічого ще не створено.
        """
        shutil.rmtree(self.bin_dir)
        shutil.rmtree(self.data_dir)

        result = self.run_guard(
            'reclaim_root_owned_paths "$(id -un)"; echo DONE', uid=int(os.getuid())
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DONE", result.stdout)


class TestDropRootPrivileges(PrivilegeDropTestCase):
    def test_non_root_run_is_a_no_op(self) -> None:
        """Звичайний запуск не має виконувати жодного дії.

        Найважливіший випадок: оператор запускає `./start.sh` без sudo
        майже завжди, і цей шлях не повинен ані щось переписувати,
        ані змінювати `HOME`.
        """
        result = self.run_guard('drop_root_privileges "$@"; echo DONE', uid=int(os.getuid()))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DONE", result.stdout)
        self.assertNotIn("продовжуємо від користувача", result.stdout)

    def test_root_without_target_user_dies_with_instruction(self) -> None:
        """Без користувача, від якого продовжити, — зупинка з підказкою.

        Інакше скрипт або працював би далі від root (і знову поламав
        би стенд), або впав би десь пізніше з незрозумілою помилкою.
        """
        result = self.run_guard(
            'drop_root_privileges "$@"',
            uid=0,
            sudo_user="rr-nonexistent-user-9182734",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("sudo", result.stderr)
        # Підказка має називати правильний виклик, а не лише слово sudo.
        self.assertRegex(result.stderr, r"\./start\.sh")

    def test_root_with_target_user_re_execs_through_setpriv(self) -> None:
        """Гілка root має перезапустити скрипт від звичайного користувача.

        Перевіряється саме команда `setpriv`: саме вона знижує права.
        Якщо її прибрати, скрипт піде далі від root — тобто повернути
        власність `data/` і запустити Firefox під root, що і є поломкою,
        яку ми виправляємо.
        """
        current = subprocess.run(
            ["id", "-un"], capture_output=True, text=True, check=True
        ).stdout.strip()

        # `exec setpriv ...` замінює процес, тому підміняємо `setpriv`
        # на програму, яка лише друкує свої аргументи й завершується.
        bindir = self.tmp / "bin"
        bindir.mkdir(exist_ok=True)
        fake_setpriv = bindir / "setpriv"
        fake_setpriv.write_text('#!/bin/sh\necho "SETPRIV $*"\n', encoding="utf-8")
        fake_setpriv.chmod(0o755)

        result = self.run_guard(
            'drop_root_privileges "$@"',
            uid=0,
            sudo_user=current,
            env={"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SETPRIV", result.stdout)

        invocation = next(
            line for line in result.stdout.splitlines() if line.startswith("SETPRIV")
        )

        # Зниження реального і ефективного uid/gid саме на користувача.
        self.assertIn(f"--reuid={current}", invocation)
        self.assertIn(f"--regid={current}", invocation)
        # Групи мають бути ініціалізовані, інакше `browser-worker`
        # втратить доступ до власних файлів.
        self.assertIn("--init-groups", invocation)
        # `HOME` має вказувати на каталог користувача, інакше Firefox
        # піде у `/root/.cache` — саме те, через що він не запускався.
        self.assertRegex(invocation, r"env HOME=/")

        # Перезапуск має йти на `start.sh`, а не на вивідений із
        # `BASH_SOURCE` уривок імені. Ім'я, виведене з `BASH_SOURCE[0]`,
        # під `sudo ./start.sh` не збігається з реальним шляхом виконуваного
        # файла, тож перезапуск пішов би у файл, якого немає.
        self.assertIn(str(START_SH), invocation)


class TestRealFirefoxLaunches(PrivilegeDropTestCase):
    """Живий рушій: Firefox має запускатися на цій машині.

    Тест не доводить, що Firefox не запускається від root —sudo на
    цій машині вимагає пароля, і тест його не має. Він доводить
    зворотне: браузер справний, отже поломка стенду має дещо інше
    походження, ніж збірка Firefox чи системні бібліотеки.
    """

    def test_firefox_141_launches_with_playwright(self) -> None:
        workers_venv = self.tmp / "venv"
        try:
            subprocess.run(
                ["python3", "-m", "venv", str(workers_venv)],
                check=True,
                capture_output=True,
                timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            self.skipTest(f"не вдалося створити venv: {error}")

        python = workers_venv / "bin" / "python"
        try:
            subprocess.run(
                [str(python), "-m", "pip", "install", "--quiet", "playwright==1.55.0"],
                check=True,
                capture_output=True,
                timeout=900,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            self.skipTest(f"не вдалося встановити playwright: {error}")

        browsers = self.tmp / "browsers"
        env = dict(os.environ)
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)
        try:
            subprocess.run(
                [str(python), "-m", "playwright", "install", "firefox"],
                check=True,
                capture_output=True,
                timeout=1800,
                env=env,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            self.skipTest(f"не вдалося завантажити Firefox: {error}")

        probe = self.tmp / "probe.py"
        probe.write_text(
            "from playwright.sync_api import sync_playwright\n"
            "\n"
            "with sync_playwright() as p:\n"
            "    browser = p.firefox.launch(headless=True)\n"
            "    page = browser.new_page()\n"
            '    page.set_content("<h1>rr</h1>")\n'
            '    assert page.inner_text("h1") == "rr"\n'
            "    browser.close()\n"
            'print("LAUNCH_OK")\n',
            encoding="utf-8",
        )

        result = subprocess.run(
            [str(python), str(probe)],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )

        self.assertEqual(
            result.returncode,
            0,
            "Firefox не запустився від звичайного користувача — "
            "збирання або системні бібліотеки, а не запуск від root:\n"
            f"{result.stdout}\n{result.stderr}",
        )
        self.assertIn("LAUNCH_OK", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)