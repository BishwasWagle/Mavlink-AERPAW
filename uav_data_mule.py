#!/usr/bin/env python3
# sequential_fly_spoof_demo.py
"""
Sequential AERPAW Flight + Spoof Demo Triggered by Plaintext vs Encrypted Commands

Behavior you requested:
- Drone flies sequentially through visit_order.
- When it reaches BS2 (or the configured spoof_trigger_bs):
    - If it has seen a PLAINTEXT command (receiver writes "plain|GOTO|..."), it deviates 90m east.
    - If it has seen an ENCRYPTED command (receiver writes "enc|GOTO|...") OR secure flag exists,
      it discards spoofing and returns home and lands.
- If messages are always encrypted, spoofing should not occur.

Mechanism:
- receiver_cmd.py writes:
    /tmp/flight_cmd.txt  => "plain|GOTO|lat,lon,alt" or "enc|GOTO|lat,lon,alt"
    /tmp/secure_ok.flag  => present when an encrypted command was verified+decrypted

Usage:
  python3 sequential_fly_spoof_demo.py --safety_checker_ip <IP> --safety_checker_port <PORT> --dwell 3 --speed 10 --alt 25

Notes:
- "Home" for landing is vehicle.home_coords (RTL). The GOTO coordinates are used only as a trigger and for logging.
- Spoof deviation is done as a deliberate wrong waypoint command (safe + reproducible).
"""

import asyncio
import datetime
import csv
import os
import math
from typing import List
from argparse import ArgumentParser

from aerpawlib.runner import StateMachine, state, background
from aerpawlib.aerpaw import AERPAW_Platform
from aerpawlib.vehicle import Vehicle, Drone
from aerpawlib.util import Coordinate
from aerpawlib.safetyChecker import SafetyCheckerClient


# === WAYPOINTS (Base Stations) ===
bs_data_list = [
    { "id": 0, "name": "start", "coordinates": { "latitude": 35.727367,  "longitude": -78.69655491282358 }, "intermediary": None },
    { "id": 1, "name": "bs1",   "coordinates": { "latitude": 35.7275287, "longitude": -78.6962216 },      "intermediary": None },
    { "id": 2, "name": "bs2",   "coordinates": { "latitude": 35.72826,   "longitude": -78.70060 },        "intermediary": None },
    # { "id": 2, "name": "bs2",   "coordinates": { "latitude": 35.724845,  "longitude": -78.6920629 },
    #   "intermediary": { "latitude": 35.724845, "longitude": -78.69655491282358 } },
    { "id": 3, "name": "bs3",   "coordinates": { "latitude": 35.7275287, "longitude": -78.6962216 },      "intermediary": None },
]

CMD_FILE = "/tmp/flight_cmd.txt"

class SequentialFlyerSpoofDemo(StateMachine):
    # Flight params
    uav_altitude = 25.0
    target_speed = 10.0
    dwell_seconds = 3.0

    # Visit order: A -> bs1 -> bs2 -> bs3 -> bs4 -> A
    visit_order = [1, 2, 3]

    # Spoof demo config
    enable_spoof_demo = True
    spoof_trigger_bs = 2          # spoof decision at BS2 arrival
    spoof_offset_east_m = 90    # deviate 90m east
    override_wait_s = 20.0
    spoof_hold_wait_s = 30.0       # after spoof, wait up to N sec for encrypted override
    in_hold = False
    # internal state
    start_time = None
    idx = 0

    secure_ok = False
    last_cmd = None  # (mode, cmd, lat, lon, alt)

    def initialize_args(self, extra_args: List[str]):
        directory = "/root/Results"
        os.makedirs(directory, exist_ok=True)

        default_file = os.path.join(
            directory,
            f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_vehicleOut.txt"
        )

        parser = ArgumentParser()
        parser.add_argument("--safety_checker_ip", required=True, help="Safety checker IP")
        parser.add_argument("--safety_checker_port", required=True, help="Safety checker port")

        parser.add_argument("--output", required=False, default=default_file)
        parser.add_argument("--samplerate", required=False, type=float, default=1.0)

        parser.add_argument("--dwell", required=False, type=float, default=self.dwell_seconds)
        parser.add_argument("--speed", required=False, type=float, default=self.target_speed)
        parser.add_argument("--alt", required=False, type=float, default=self.uav_altitude)

        parser.add_argument("--enable_spoof", action="store_true", help="Enable plaintext-triggered spoof demo")
        parser.add_argument("--disable_spoof", action="store_true", help="Disable spoof demo")
        parser.add_argument("--spoof_bs", type=int, default=self.spoof_trigger_bs, help="BS id where spoof is triggered")
        parser.add_argument("--spoof_east_m", type=float, default=self.spoof_offset_east_m, help="Spoof offset east (meters)")
        parser.add_argument("--override_wait_s", type=float, default=self.override_wait_s, help="Wait for encrypted override (seconds)")

        args = parser.parse_args(args=extra_args)

        self.safety_checker = SafetyCheckerClient(args.safety_checker_ip, args.safety_checker_port)
        self.dwell_seconds = float(args.dwell)
        self.target_speed = float(args.speed)
        self.uav_altitude = float(args.alt)

        self.spoof_trigger_bs = int(args.spoof_bs)
        self.spoof_offset_east_m = float(args.spoof_east_m)
        self.override_wait_s = float(args.override_wait_s)

        # spoof toggle
        if args.disable_spoof:
            self.enable_spoof_demo = False
        elif args.enable_spoof:
            self.enable_spoof_demo = True

        # light logging
        self._sampling_delay = 1.0 / float(args.samplerate)
        self._log_file = open(args.output, "w+")
        self._csv_writer = csv.writer(self._log_file)
        self._csv_writer.writerow(["ts", "state", "lat", "lon", "alt", "idx", "secure_ok", "last_cmd"])
        self._log_file.flush()

    def log_row(self, vehicle: Vehicle, state_name: str):
        pos = vehicle.position
        ts = datetime.datetime.utcnow().isoformat()
        self._csv_writer.writerow([
            ts,
            state_name,
            pos.lat if pos else None,
            pos.lon if pos else None,
            pos.alt if pos else None,
            self.idx,
            int(self.secure_ok),
            str(self.last_cmd) if self.last_cmd else ""
        ])
        self._log_file.flush()

    @background
    async def sampler(self, vehicle: Vehicle):
        while True:
            try:
                self.log_row(vehicle, "sampler")
            except Exception:
                pass
            await asyncio.sleep(self._sampling_delay)

    @background
    async def watch_cmd(self):
        """Watch receiver-published files and update flags."""
        while True:
            try:
                if os.path.exists(CMD_FILE):
                    line = open(CMD_FILE, "r").read().strip()
                    # mode|CMD|lat,lon,alt
                    mode, cmd, coords = line.split("|")
                    lat_s, lon_s, alt_s = coords.split(",")
                    self.last_cmd = (mode, cmd, float(lat_s), float(lon_s), float(alt_s))
            except Exception:
                pass
            await asyncio.sleep(0.2)

    def bs_to_coord(self, bs_id: int) -> Coordinate:
        bs = bs_data_list[bs_id]
        print(Coordinate(bs["coordinates"]["latitude"], bs["coordinates"]["longitude"], self.uav_altitude), "================")
        return Coordinate(bs["coordinates"]["latitude"], bs["coordinates"]["longitude"], self.uav_altitude)

    def offset_east(self, base: Coordinate, east_m: float) -> Coordinate:
        # east => negative East meters
        east_m = east_m
        dlon = east_m / (111111.0 * math.cos(math.radians(base.lat)))
        return Coordinate(lat=base.lat, lon=base.lon + dlon, alt=base.alt)

    async def go_to(self, vehicle: Drone, next_pos: Coordinate, timeout_s=None) -> bool:
        """Turn, safety-check, then goto. If timeout_s is None, wait indefinitely."""
        cur_pos = vehicle.position
        if cur_pos is None:
            return False

        # Turn (you can keep this timeout; it's not a mission-timeout, just avoids hanging forever)
        new_heading = cur_pos.bearing(next_pos)
        try:
            await asyncio.wait_for(vehicle.set_heading(new_heading), timeout=10.0)
        except asyncio.TimeoutError:
            print("[WARN] set_heading timed out")
            # Not fatal; you can still try to fly
            # return False

        # Safety check
        valid, msg = self.safety_checker.validateWaypointCommand(cur_pos, next_pos)
        if not valid:
            print(f"[SAFETY] Waypoint rejected: {msg}")
            return False

        # Move
        if timeout_s is None:
            await vehicle.goto_coordinates(next_pos)   # wait indefinitely
            return True

        try:
            await asyncio.wait_for(vehicle.goto_coordinates(next_pos), timeout=timeout_s)
            return True
        except asyncio.TimeoutError:
            print(f"[WARN] goto_coordinates timed out after {timeout_s}s")
            return False


    @state(name="start", first=True)
    async def start(self, vehicle: Drone):
        # --- CLEANUP stale command/secure flags from previous runs ---
        if os.path.exists(CMD_FILE):
            os.remove(CMD_FILE)
        self.last_cmd = None
        asyncio.ensure_future(self.sampler(vehicle))
        asyncio.ensure_future(self.watch_cmd())

        await vehicle.takeoff(self.uav_altitude)
        await vehicle.set_groundspeed(self.target_speed)

        self.start_time = datetime.datetime.now()
        AERPAW_Platform.log_to_oeo(f"Takeoff to {self.uav_altitude}m; speed={self.target_speed}m/s")
        return "go_next"

    @state(name="hold_spoofed")
    async def hold_spoofed(self, vehicle: Drone):
        AERPAW_Platform.log_to_oeo("Holding at spoofed location. Waiting for ENC to RTL...")

        # Optional: reduce speed so it doesn't try to continue anywhere
        try:
            await vehicle.set_groundspeed(0)
        except Exception:
            pass

        while True:
            # If ENC command arrives anytime, return home and land
            if self.last_cmd and self.last_cmd[0] == "enc":
                AERPAW_Platform.log_to_oeo("ENC received while holding -> RTL + land")
                return "return_to_launch_and_land"

            # Keep holding
            await asyncio.sleep(0.5)

    @state(name="go_next")
    async def go_next(self, vehicle: Drone):
        # Finished route -> land
        if self.idx >= len(self.visit_order):
            return "return_to_launch_and_land"

        target_bs_id = self.visit_order[self.idx]
        next_pos = self.bs_to_coord(target_bs_id)

        AERPAW_Platform.log_to_oeo(
            f"Going to BS{target_bs_id} ({self.idx+1}/{len(self.visit_order)})"
        )

        moved = await self.go_to(vehicle, next_pos, timeout_s=None)
        if not moved:
            return "return_to_launch_and_land"

        if self.dwell_seconds > 0:
            AERPAW_Platform.log_to_oeo(f"Arrived BS{target_bs_id}; dwell {self.dwell_seconds}s")
            await asyncio.sleep(self.dwell_seconds)

        # ---- Spoof decision point at BS2 ----
        if self.enable_spoof_demo and target_bs_id == self.spoof_trigger_bs:

            # If ENC already received any time before -> DO NOT spoof, continue mission
            if self.last_cmd and self.last_cmd[0] == "enc":
                AERPAW_Platform.log_to_oeo("ENC already present -> do NOT spoof; continue mission")
                self.idx += 1
                return "go_next"

            # If PLAINTEXT observed -> spoof, then wait 30s for ENC
            if self.last_cmd and self.last_cmd[0] == "plain":
                AERPAW_Platform.log_to_oeo(
                    f"PLAINTEXT observed -> SPOOF: deviate {self.spoof_offset_east_m:.0f}m east"
                )

                cur = vehicle.position
                base = Coordinate(cur.lat, cur.lon, self.uav_altitude)
                spoof_pos = self.offset_east(base, self.spoof_offset_east_m)

                moved_spoof = await self.go_to(vehicle, spoof_pos, timeout_s=None)
                if moved_spoof:
                    AERPAW_Platform.log_to_oeo("Spoof waypoint reached. Waiting 30s for ENC...")
                else:
                    AERPAW_Platform.log_to_oeo("Spoof waypoint blocked by safety; holding anyway.")
                    return "hold_spoofed"

                t0 = datetime.datetime.now()
                while (datetime.datetime.now() - t0).total_seconds() < self.spoof_hold_wait_s:
                    if self.last_cmd and self.last_cmd[0] == "enc":
                        AERPAW_Platform.log_to_oeo("ENC received within 30s -> RTL + land")
                        return "return_to_launch_and_land"
                    await asyncio.sleep(0.2)

                # No ENC within 30s -> HOLD indefinitely
                AERPAW_Platform.log_to_oeo("No ENC within 30s -> holding at spoofed location indefinitely")
                return "hold_spoofed"

            # If neither plain nor enc exists, just continue mission (no spoof)
            AERPAW_Platform.log_to_oeo("No command observed at trigger -> continue mission")

        # Normal progression (only reached if not spoof-holding / not RTL)
        self.idx += 1
        return "go_next"


    @state(name="return_to_launch_and_land")
    async def return_to_launch_and_land(self, vehicle: Drone):
        print("Return to launch and landing.")

        # Go home (vehicle.home_coords) and land
        home = Coordinate(vehicle.home_coords.lat, vehicle.home_coords.lon, vehicle.position.alt)

        ok = await self.go_to(vehicle, home, timeout_s=120.0)
        if not ok:
            print("[WARN] Could not reach home within timeout. Landing in place for safety.")
        await vehicle.land()

        seconds = (datetime.datetime.now() - self.start_time).total_seconds() if self.start_time else None
        AERPAW_Platform.log_to_oeo(f"Done. Flight time={seconds:.1f}s" if seconds else "Done.")
        return None

