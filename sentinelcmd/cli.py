"""Terminal menu and scriptable commands for the same local monitoring engine."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

from . import __version__
from .collectors import SystemInspector, build_process_tree
from .config import ConfigManager, default_data_dir, validate_config
from .detection import RuleEngine
from .monitor import Monitor
from .privacy import safe_text
from .response import FirewallManager, QuarantineManager, terminate_process
from .storage import EventStore


def emit(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=True, default=str))


def table(records: list[dict], columns: list[tuple[str, str, int]]) -> None:
    print("  ".join(title.ljust(width) for _, title, width in columns))
    print("  ".join("-" * width for _, _, width in columns))
    for record in records:
        print("  ".join(safe_text(record.get(key), width).ljust(width) for key, _, width in columns))
    print(f"{len(records)} registro(s).")


def confirm(message: str, yes: bool = False) -> None:
    if yes:
        return
    if not sys.stdin.isatty():
        raise ValueError("Acao requer --yes em execucao nao interativa.")
    if input(f"{message} Digite SIM para confirmar: ").strip() != "SIM":
        raise ValueError("Acao cancelada.")


class Application:
    def __init__(self, data_dir: Path, config_path: Path | None = None):
        self.data_dir = data_dir.expanduser().resolve()
        self.manager = ConfigManager(self.data_dir, config_path)
        self.config = self.manager.load()
        # Fail on malformed rule configuration before opening the event database.
        RuleEngine(self.config)
        self.store = EventStore(self.data_dir, self.config)
        self.monitor = Monitor(self.config, self.data_dir, self.store)
        self.quarantine = QuarantineManager(self.data_dir, protected_paths=[Path(__file__).resolve().parents[1]])
        self.firewall = FirewallManager()

    def update_config(self, key: str, value: object) -> dict:
        config = validate_config({**self.config, key: value})
        RuleEngine(config)
        running = self.monitor.running
        self.monitor.close()
        self.config = self.manager.save(config)
        self.store.config = self.config
        self.monitor = Monitor(self.config, self.data_dir, self.store)
        if running:
            self.monitor.start()
        return self.config

    def audit_action(self, operation: str, result: dict, **record: object) -> dict:
        status = result.get("status", "unconfirmed")
        action = "firewall_blocked" if status == "blocked" and result.get("created") else status
        self.store.append({"kind": "manual_response", "operation": operation,
                           "result": result, **record}, action=str(action))
        return result

    def investigate(self, event_id: str) -> dict:
        matches = self.store.query(event_id=event_id)
        if not matches:
            raise ValueError("Evento nao encontrado (pode ter expirado pela retencao).")
        event = matches[0]
        if not event.get("pid") or not event.get("process_created_at"):
            return {"event": event, "ancestry": [], "timeline": [event],
                    "note": "Sem identidade de processo comprovada; autoria nao pode ser inferida."}
        records = self.store.query(limit=self.config["max_events"])
        identities = {}
        for record in records:
            if record.get("pid") is not None and record.get("process_created_at"):
                identities.setdefault((record["pid"], record["process_created_at"]), record)
        key = (event["pid"], event["process_created_at"])
        timeline = [r for r in reversed(records) if (r.get("pid"), r.get("process_created_at")) == key]
        ancestry, visited = [], set()
        current = event
        while current and len(ancestry) < 32:
            identity = (current.get("pid"), current.get("process_created_at"))
            if identity in visited:
                break
            visited.add(identity)
            ancestry.append({field: current.get(field) for field in (
                "pid", "ppid", "process_created_at", "parent_created_at", "process_name", "executable")})
            current = identities.get((current.get("ppid"), current.get("parent_created_at")))
        return {"event": event, "ancestry": list(reversed(ancestry)), "timeline": timeline,
                "note": "Cadeia observada, limitada pela coleta/permissoes/retencao; lacunas nao sao inferidas."}

    def close(self) -> None:
        self.monitor.close()
        self.store.close()


def show_processes(app: Application, tree: bool = False, as_json: bool = False) -> None:
    records = app.monitor.processes.snapshot()
    if as_json:
        # Apply the same privacy policy to command-line output as to storage.
        from .privacy import command_line_for_storage
        for record in records:
            record["command_line"] = command_line_for_storage(record.get("command_line"),
                                                               app.config["store_command_lines"])
        emit(records)
    elif tree:
        print(build_process_tree(records))
    else:
        table(records, [("pid", "PID", 7), ("ppid", "PPID", 7), ("process_name", "PROCESS", 24),
                        ("username", "USER", 24), ("executable", "EXECUTABLE", 70)])
    if app.monitor.processes.last_error:
        print("Cobertura parcial: " + safe_text(app.monitor.processes.last_error), file=sys.stderr)


def show_network(app: Application, as_json: bool = False) -> None:
    records = app.monitor.network.snapshot()
    if as_json:
        emit(records)
    else:
        for record in records:
            record["local"] = f"{record.get('local_ip') or '*'}:{record.get('local_port') or '*'}"
            record["remote"] = f"{record.get('remote_ip') or '*'}:{record.get('remote_port') or '*'}"
        table(records, [("process_name", "PROCESS", 22), ("pid", "PID", 7), ("protocol", "PROTO", 5),
                        ("local", "LOCAL", 30), ("remote", "REMOTE", 30), ("state", "STATE", 14)])
    if app.monitor.network.last_error:
        print("Cobertura parcial: " + safe_text(app.monitor.network.last_error), file=sys.stderr)


def show_events(app: Application, limit: int = 30, min_score: int = 0, pid: int | None = None,
                event_id: str | None = None, as_json: bool = False) -> None:
    events = app.store.query(limit, min_score, pid, event_id)
    if as_json or event_id:
        emit(events)
        return
    for event in events:
        print(f"\n[{safe_text(event['risk']).upper()} {event['score']}/100] "
              f"{safe_text(event['timestamp'])} {safe_text(event['kind'])}")
        print(f"  ID: {event['id']} | Acao: {safe_text(event['action'])}")
        print(f"  Processo: {safe_text(event.get('process_name'))} PID={event.get('pid')} "
              f"PPID={event.get('ppid')} | Usuario: {safe_text(event.get('username'))}")
        print(f"  Arquivo: {safe_text(event.get('file_path') or event.get('executable'))}")
        print(f"  SHA256: {safe_text(event.get('sha256'))}")
        print(f"  Rede: {safe_text(event.get('local_ip'))}:{safe_text(event.get('local_port'))} -> "
              f"{safe_text(event.get('remote_ip'))}:{safe_text(event.get('remote_port'))} "
              f"{safe_text(event.get('protocol'))}")
        if event.get("reasons"):
            print("  Motivos: " + "; ".join(safe_text(reason) for reason in event["reasons"]))
    print(f"\n{len(events)} evento(s). Horarios UTC; risco heuristico nao confirma malware.")


def show_dashboard(app: Application) -> None:
    status = app.monitor.status()
    print("\n+------------------------------------------+")
    print("|               SENTINEL CMD               |")
    print("|        Endpoint Security Monitor         |")
    print("+------------------------------------------+")
    print(f"Status: {status['status']} | Camada adicional de monitoramento")
    cpu = f"{status['cpu_percent']:.1f}%" if status["cpu_percent"] is not None else "indisponivel"
    memory = f"{status['ram_mb']:.1f} MB" if status["ram_mb"] is not None else "indisponivel"
    print(f"CPU Sentinel: {cpu} | RAM Sentinel: {memory}")
    print(f"Acoes de bloqueio hoje (UTC): {status['blocked_today_utc']} | "
          f"Eventos suspeitos: {status['suspicious_today_utc']}")
    print(f"Conexoes no ultimo inventario: {status['active_connections']}")
    if status["health"]:
        print("Cobertura: " + safe_text(status["health"]))
    print("\n[1] Start Protection      [2] Stop Protection       [3] Security Scan")
    print("[4] Live Processes        [5] Network Connections   [6] File Monitor")
    print("[7] Threats               [8] Quarantine            [9] Security Logs")
    print("[10] Firewall             [11] Rules                [12] System Security")
    print("[13] Export Report        [14] Settings             [0] Exit")


def menu(app: Application) -> int:
    while True:
        show_dashboard(app)
        try:
            choice = input("\nSentinel > ").strip()
            if choice == "0":
                return 0
            if choice == "1":
                print("Monitor iniciado." if app.monitor.start() else "Monitor ja esta ativo.")
            elif choice == "2":
                app.monitor.stop()
                print("Monitor parado. Regras de firewall existentes permanecem ate remocao explicita.")
            elif choice == "3":
                result = app.monitor.scan()
                print(f"{result['processes_scanned']} processos, {result['connections_scanned']} conexoes, "
                      f"{len(result['alerts'])} novo(s) alerta(s) exibivel(is).")
                show_events(app, min_score=1, limit=10)
            elif choice == "4":
                show_processes(app, tree=input("Arvore? [s/N] ").lower() == "s")
                print("Atualizacao continua: sentinel processes --watch 3")
            elif choice == "5":
                show_network(app)
            elif choice == "6":
                emit({"paths": app.config["monitor_paths"], "status": app.monitor.files.status})
                path = input("Adicionar pasta local absoluta (Enter para voltar): ").strip()
                if path:
                    app.update_config("monitor_paths", app.config["monitor_paths"] + [path])
            elif choice in ("7", "9"):
                show_events(app, min_score=1 if choice == "7" else 0)
                event_id = input("ID para investigar (Enter para voltar): ").strip()
                if event_id:
                    emit(app.investigate(event_id))
            elif choice == "8":
                emit(app.quarantine.list_items())
                operation = input("[a] adicionar [r] restaurar [d] excluir [Enter] voltar: ").strip()
                if operation == "a":
                    path = Path(input("Arquivo local: ").strip())
                    confirm(f"Mover {safe_text(path)} para quarentena?")
                    emit(app.audit_action("quarantine", app.quarantine.quarantine(path), file_path=str(path)))
                elif operation in ("r", "d"):
                    item_id = input("ID: ").strip()
                    confirm("Restaurar arquivo?" if operation == "r" else "Excluir bytes permanentemente?")
                    result = app.quarantine.restore(item_id) if operation == "r" else app.quarantine.delete(item_id)
                    emit(app.audit_action("restore" if operation == "r" else "delete", result))
            elif choice == "10":
                operation = input("[l] listar [b] bloquear IP publico [r] remover regra: ").strip()
                if operation == "l":
                    emit(app.firewall.list_rules())
                elif operation == "b":
                    address = input("IP: ").strip()
                    confirm(f"Bloquear conexoes de saida para {safe_text(address)}?")
                    emit(app.audit_action("firewall_block", app.firewall.block_ip(address), remote_ip=address))
                elif operation == "r":
                    rule_id = input("ID da regra SentinelCMD: ").strip()
                    confirm("Remover esta regra de firewall?")
                    emit(app.audit_action("firewall_remove", app.firewall.remove_rule(rule_id)))
            elif choice == "11":
                emit(app.monitor.engine.list_rules())
            elif choice == "12":
                emit(SystemInspector().inspect())
            elif choice == "13":
                path = Path(input("Novo arquivo de relatorio (.json ou .csv): ").strip())
                emit(app.store.export(path, "csv" if path.suffix.lower() == ".csv" else "json"))
            elif choice == "14":
                emit({"config_path": str(app.manager.path), "settings": app.config})
                key = input("Opcao para alterar (Enter para voltar): ").strip()
                if key:
                    value = json.loads(input("Novo valor em JSON: "))
                    app.update_config(key, value)
            else:
                print("Opcao invalida.")
        except (EOFError, KeyboardInterrupt):
            print("\nEncerrando monitoramento.")
            return 0
        except (ValueError, OSError, RuntimeError) as exc:
            print("Erro: " + safe_text(exc))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sentinel", description="SentinelCMD: monitoramento defensivo local")
    root.add_argument("--version", action="version", version=f"SentinelCMD {__version__}")
    root.add_argument("--data-dir", type=Path, default=default_data_dir())
    root.add_argument("--config", type=Path, help="Arquivo JSON de configuracao")
    commands = root.add_subparsers(dest="command")
    run = commands.add_parser("run", help="Monitor em primeiro plano, Ctrl+C para parar")
    run.add_argument("--duration", type=float, help="Parar apos N segundos")
    commands.add_parser("status", help="Status desta instancia e contadores persistidos")
    commands.add_parser("scan", help="Analisar processos ativos e sockets locais; sem respostas")
    for name in ("processes", "network"):
        sub = commands.add_parser(name)
        sub.add_argument("--json", action="store_true")
        sub.add_argument("--watch", type=float, metavar="SECONDS")
        if name == "processes":
            sub.add_argument("--tree", action="store_true")
    for name in ("threats", "logs"):
        sub = commands.add_parser(name)
        sub.add_argument("--limit", type=int, default=30)
        sub.add_argument("--pid", type=int)
        sub.add_argument("--id", dest="event_id")
        sub.add_argument("--json", action="store_true")
    investigate = commands.add_parser("investigate")
    investigate.add_argument("event_id")
    files = commands.add_parser("files")
    files.add_argument("operation", choices=["status", "add", "remove"])
    files.add_argument("path", type=Path, nargs="?")
    quarantine = commands.add_parser("quarantine")
    quarantine.add_argument("operation", choices=["list", "add", "restore", "delete"])
    quarantine.add_argument("target", nargs="?")
    quarantine.add_argument("--destination", type=Path)
    quarantine.add_argument("--sha256", help="Hash esperado antes de mover para quarentena")
    quarantine.add_argument("--reason", default="Manual local investigation")
    quarantine.add_argument("--yes", action="store_true")
    firewall = commands.add_parser("firewall")
    firewall.add_argument("operation", choices=["list", "block", "remove"])
    firewall.add_argument("target", nargs="?")
    firewall.add_argument("--reason", default="Manual local investigation")
    firewall.add_argument("--yes", action="store_true")
    rules = commands.add_parser("rules")
    rules.add_argument("operation", choices=["list", "enable", "disable"], default="list", nargs="?")
    rules.add_argument("rule_id", nargs="?")
    commands.add_parser("system", help="Estado local Defender/firewall/atualizacoes")
    export = commands.add_parser("export")
    export.add_argument("path", type=Path)
    export.add_argument("--format", choices=["json", "csv"], default="json")
    export.add_argument("--alerts-only", action="store_true")
    config = commands.add_parser("config")
    config.add_argument("operation", choices=["show", "set"], default="show", nargs="?")
    config.add_argument("key", nargs="?")
    config.add_argument("value", nargs="?", help="Valor JSON, por exemplo true ou 5")
    terminate = commands.add_parser("terminate", help="Encerrar explicitamente um processo identificado")
    terminate.add_argument("pid", type=int)
    terminate.add_argument("--created-at", type=float, required=True)
    terminate.add_argument("--yes", action="store_true")
    return root


def dispatch(app: Application, args: argparse.Namespace) -> int:
    if args.command is None:
        return menu(app)
    if args.command == "run":
        if args.duration is not None and (args.duration <= 0 or not __import__("math").isfinite(args.duration)):
            raise ValueError("Duracao deve ser positiva e finita.")
        app.monitor.start()
        print("SentinelCMD monitorando localmente. Ctrl+C para parar.", flush=True)
        deadline = time.monotonic() + args.duration if args.duration else float("inf")
        try:
            while time.monotonic() < deadline and app.monitor.running:
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        except KeyboardInterrupt:
            pass
        failed = "worker" in app.monitor.status()["health"]
        app.monitor.stop()
        emit(app.monitor.status())
        return 1 if failed else 0
    if args.command == "status":
        emit({**app.monitor.status(), "note": "Status desta instancia. Outro processo nao e controlado por este comando."})
    elif args.command == "scan":
        emit(app.monitor.scan())
    elif args.command in ("processes", "network"):
        if args.watch is not None and not 1 <= args.watch <= 3600:
            raise ValueError("Intervalo --watch deve estar entre 1 e 3600 segundos.")
        try:
            while True:
                if args.command == "processes":
                    show_processes(app, args.tree, args.json)
                else:
                    show_network(app, args.json)
                if args.watch is None:
                    break
                time.sleep(args.watch)
        except KeyboardInterrupt:
            pass
    elif args.command in ("logs", "threats"):
        show_events(app, args.limit, 1 if args.command == "threats" else 0, args.pid, args.event_id, args.json)
    elif args.command == "investigate":
        emit(app.investigate(args.event_id))
    elif args.command == "files":
        if args.operation != "status":
            if args.path is None:
                raise ValueError("Forneca uma pasta local absoluta.")
            path = str(args.path.expanduser().absolute())
            paths = app.config["monitor_paths"]
            if args.operation == "add":
                if not args.path.is_dir():
                    raise ValueError("Pasta nao encontrada.")
                paths = paths + [path]
            else:
                paths = [p for p in paths if os.path.normcase(p) != os.path.normcase(path)]
            app.update_config("monitor_paths", paths)
        emit({"paths": app.config["monitor_paths"], "status": app.monitor.files.status})
    elif args.command == "quarantine":
        if args.operation == "list":
            emit(app.quarantine.list_items())
        else:
            if not args.target:
                raise ValueError("Forneca caminho ou ID conforme a operacao.")
            confirm(f"Executar quarentena/{args.operation} em {safe_text(args.target)}?", args.yes)
            if args.operation == "add":
                result = app.quarantine.quarantine(Path(args.target), args.reason, args.sha256)
            elif args.operation == "restore":
                result = app.quarantine.restore(args.target, args.destination)
            else:
                result = app.quarantine.delete(args.target)
            emit(app.audit_action("quarantine_" + args.operation, result))
    elif args.command == "firewall":
        if args.operation == "list":
            emit(app.firewall.list_rules())
        else:
            if not args.target:
                raise ValueError("Forneca IP ou ID da regra conforme a operacao.")
            confirm(f"Executar firewall/{args.operation} em {safe_text(args.target)}?", args.yes)
            result = app.firewall.block_ip(args.target, args.reason) if args.operation == "block" \
                else app.firewall.remove_rule(args.target)
            emit(app.audit_action("firewall_" + args.operation, result))
    elif args.command == "rules":
        if args.operation != "list":
            rule_ids = {r["id"] for r in app.monitor.engine.list_rules()}
            if args.rule_id not in rule_ids:
                raise ValueError("ID de regra desconhecido.")
            disabled = set(app.config["disabled_rules"])
            if args.operation == "disable":
                disabled.add(args.rule_id)
            else:
                disabled.discard(args.rule_id)
            app.update_config("disabled_rules", sorted(disabled))
        emit(app.monitor.engine.list_rules())
    elif args.command == "system":
        emit(SystemInspector().inspect())
    elif args.command == "export":
        emit(app.store.export(args.path, args.format, 1 if args.alerts_only else 0))
    elif args.command == "config":
        if args.operation == "set":
            if not args.key or args.value is None:
                raise ValueError("Use config set CHAVE VALOR_JSON.")
            app.update_config(args.key, json.loads(args.value))
        emit({"path": str(app.manager.path), "settings": app.config})
    elif args.command == "terminate":
        confirm(f"Encerrar PID {args.pid} com a identidade informada?", args.yes)
        emit(app.audit_action("terminate", terminate_process(args.pid, args.created_at), pid=args.pid,
                              process_created_at=args.created_at))
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    args = parser().parse_args(argv)
    app = None
    try:
        app = Application(args.data_dir, args.config)
        return dispatch(app, args)
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, RuntimeError) as exc:
        print("SentinelCMD: " + safe_text(exc), file=sys.stderr)
        return 1
    finally:
        if app:
            app.close()
