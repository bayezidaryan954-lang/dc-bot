import asyncio
import json
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

import discord
from discord import app_commands
from discord.ext import commands

# ============================================================
#            PROFESSIONAL DISCORD MODERATION BOT - FIXED
# ============================================================
TOKEN = os.getenv("DISCORD_TOKEN") or os.getenv("BOT_TOKEN")
TEST_GUILD_ID = 0
DATA_FILE = "modbot_data.json"
REJOIN_CONTACT = "sojib_rema"
REJOIN_CONTACT_2 = "bsw_77"

# ------------------------- Intents ---------------------------
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

# -------------------------- Defaults -------------------------
def default_guild_config():
    return {
        "server_active": False,
        "log_channel": 0,
        "bad_words": [],
        "warnings": {},
        "antispam": True,
        "anti_invite": True,
        "anti_links": False,
        "anticaps": False,
        "anti_image": False,
        "anti_media_spam": True,
        "spam_window": 7,
        "spam_threshold": 6,
        "spam_timeout_minutes": 1,
        "rejoin_protection": True,
        "left_members": {},
        "antinuke": True,
        "protected_users": [],
        "protected_roles": [],
        "nuke_window": 10,
        "nuke_thresholds": {
            "ban": 3,
            "kick": 4,
            "channel_delete": 3,
            "channel_create": 5,
            "channel_update": 5,
            "role_delete": 3,
            "role_create": 4,
            "role_update": 5,
            "overwrite_create": 5,
            "overwrite_update": 5,
            "overwrite_delete": 5,
            "webhook_create": 3,
            "webhook_update": 3,
            "webhook_delete": 3,
            "member_role_update": 5,
            "bot_add": 1,
            "guild_update": 3,
        },
        "anti_raid": True,
        "raid_window": 10,
        "raid_threshold": 8,
        "security_events": 0,
    }


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"guilds": {}}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"guilds": {}}
    if not isinstance(data, dict) or "guilds" not in data:
        return {"guilds": {}}
    return data


data = load_data()


def save_data():
    temp = DATA_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp, DATA_FILE)


def merge_defaults(config: dict):
    defaults = default_guild_config()
    changed = False
    for key, value in defaults.items():
        if key not in config:
            config[key] = value
            changed = True

    # FIX: safely ensure nuke_thresholds exists
    if not isinstance(config.get("nuke_thresholds"), dict):
        config["nuke_thresholds"] = defaults["nuke_thresholds"].copy()
        changed = True
    else:
        for key, value in defaults["nuke_thresholds"].items():
            if key not in config["nuke_thresholds"]:
                config["nuke_thresholds"][key] = value
                changed = True

    for list_key in ("bad_words", "protected_users", "protected_roles"):
        if not isinstance(config.get(list_key), list):
            config[list_key] = []
            changed = True

    if not isinstance(config.get("left_members"), dict):
        config["left_members"] = {}
        changed = True

    if not isinstance(config.get("warnings"), dict):
        config["warnings"] = {}
        changed = True

    if changed:
        save_data()


def get_config(guild_id: int):
    guilds = data.setdefault("guilds", {})
    key = str(guild_id)
    if key not in guilds:
        guilds[key] = default_guild_config()
        save_data()
    merge_defaults(guilds[key])
    return guilds[key]


# ------------------------- Runtime caches --------------------
spam_cache = defaultdict(lambda: deque(maxlen=100))
media_cache = defaultdict(lambda: deque(maxlen=12))
raid_cache = defaultdict(lambda: deque(maxlen=50))
nuke_cache = defaultdict(lambda: deque(maxlen=30))
seen_audit_entries = deque(maxlen=5000)
webhook_scan_lock = defaultdict(asyncio.Lock)
rejoin_handling = set()
rejoin_locks = defaultdict(asyncio.Lock)
audit_event_locks = defaultdict(asyncio.Lock)
nuke_triggered = set()
# FIX: locks to prevent double messages
spam_locks = defaultdict(asyncio.Lock)
media_locks = defaultdict(asyncio.Lock)
raid_locks = defaultdict(asyncio.Lock)
nuke_action_locks = defaultdict(asyncio.Lock)


def utc_now():
    return datetime.now(timezone.utc)


def now_text():
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")


def clean_reason(reason: Optional[str]):
    reason = (reason or "No reason provided").strip()
    return reason[:500]


def parse_on_off(value: str):
    value = value.lower().strip()
    if value in {"on", "true", "enable", "enabled", "yes", "1"}:
        return True
    if value in {"off", "false", "disable", "disabled", "no", "0"}:
        return False
    return None


def fmt_member(member):
    return f"{member.mention if hasattr(member, 'mention') else member} (`{member.id}`)"


async def try_dm(user, message: str):
    try:
        await user.send(message)
        return True
    except (discord.Forbidden, discord.HTTPException, AttributeError):
        return False


async def send_log(guild: discord.Guild, title: str, description: str, *, color=None):
    if color is None:
        color = discord.Color.blurple()
    cfg = get_config(guild.id)
    channel_id = int(cfg.get("log_channel", 0) or 0)
    if not channel_id:
        return
    channel = guild.get_channel(channel_id)
    if not isinstance(channel, discord.TextChannel):
        return
    embed = discord.Embed(
        title=title,
        description=description[:4096],
        color=color,
        timestamp=utc_now(),
    )
    embed.set_footer(text="Professional Mod Bot")
    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        pass


def is_protected(guild: discord.Guild, user_id: int, *, role_ids=None):
    cfg = get_config(guild.id)
    if bot.user and user_id == bot.user.id:
        return True
    if user_id == guild.owner_id:
        return True
    if user_id in {int(x) for x in cfg.get("protected_users", [])}:
        return True
    if role_ids:
        protected_roles = {int(x) for x in cfg.get("protected_roles", [])}
        if protected_roles.intersection({int(x) for x in role_ids}):
            return True
    member = guild.get_member(user_id)
    if member:
        member_role_ids = {r.id for r in member.roles}
        protected_roles = {int(x) for x in cfg.get("protected_roles", [])}
        if protected_roles.intersection(member_role_ids):
            return True
    return False


def can_moderate(invoker: discord.Member, target: discord.Member):
    if target.id == invoker.id:
        return False, "You cannot moderate yourself."
    if target.id == invoker.guild.owner_id:
        return False, "You cannot moderate the server owner."
    if target.top_role >= invoker.top_role and invoker.id != invoker.guild.owner_id:
        return False, "You cannot moderate a member with an equal or higher role."
    me = invoker.guild.me
    if me is None:
        return False, "I could not verify my role hierarchy."
    if target.top_role >= me.top_role:
        return False, "My highest role is not above that member's highest role."
    return True, ""


async def add_warning(guild: discord.Guild, user: discord.Member, moderator_id: int, reason: str):
    cfg = get_config(guild.id)
    warnings = cfg.setdefault("warnings", {})
    entries = warnings.setdefault(str(user.id), [])
    entries.append({
        "reason": clean_reason(reason),
        "moderator_id": int(moderator_id),
        "time": now_text(),
    })
    # FIX: clear slice more explicitly, avoid confusing del entries[:-50]
    if len(entries) > 50:
        entries[:] = entries[-50:]
    save_data()


def attachment_is_image(attachment: discord.Attachment):
    if attachment.content_type and attachment.content_type.lower().startswith("image/"):
        return True
    return bool(re.search(r"\.(png|jpe?g|gif|webp|bmp|tiff?|svg|avif)$", attachment.filename.lower()))


def message_has_image(message: discord.Message):
    if any(attachment_is_image(a) for a in message.attachments):
        return True
    for embed in message.embeds:
        if embed.type in {"image", "gifv"}:
            return True
        if embed.image and getattr(embed.image, "url", None):
            return True
        if embed.thumbnail and getattr(embed.thumbnail, "url", None):
            return True
    return False


# ---------------------- Audit Log Helpers --------------------
async def latest_audit_entry(guild: discord.Guild, action, *, target_id=None, window=8.0):
    try:
        async for entry in guild.audit_logs(limit=10, action=action):
            created = entry.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (utc_now() - created).total_seconds()
            if age < -2 or age > window:
                continue
            if target_id is not None:
                target = entry.target
                entry_target_id = getattr(target, "id", None)
                if entry_target_id != target_id:
                    continue
            if entry.id in seen_audit_entries:
                continue
            return entry
    except (discord.Forbidden, discord.HTTPException):
        return None
    return None


async def audit_actor_for_actions(guild: discord.Guild, actions, *, target_id=None, window=8.0):
    newest = None
    for action in actions:
        entry = await latest_audit_entry(guild, action, target_id=target_id, window=window)
        if entry and (newest is None or entry.created_at > newest.created_at):
            newest = entry
    return newest


async def neutralize_actor(guild: discord.Guild, actor_id: int, *, reason: str, source: str):
    if is_protected(guild, actor_id):
        return False
    actor = guild.get_member(actor_id)
    if actor is None:
        try:
            actor = await guild.fetch_member(actor_id)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            return False
    me = guild.me
    if me is None or actor.top_role >= me.top_role:
        return False
    try:
        await actor.ban(reason=f"Anti-Nuke | {reason}", delete_message_seconds=0)
        cfg = get_config(guild.id)
        cfg["security_events"] = int(cfg.get("security_events", 0)) + 1
        save_data()
        return True
    except (discord.Forbidden, discord.HTTPException):
        return False


def schedule_nuke_reset(trigger_key, delay=120):
    async def _reset():
        await asyncio.sleep(delay)
        nuke_triggered.discard(trigger_key)
    asyncio.create_task(_reset())


async def record_nuke_action(guild: discord.Guild, actor_id: int, action_name: str, *, target=None, details=""):
    cfg = get_config(guild.id)
    if not cfg.get("server_active", False) or not cfg.get("antinuke", True):
        return
    if is_protected(guild, actor_id):
        return
    threshold = int(cfg.get("nuke_thresholds", {}).get(action_name, 0) or 0)
    if threshold <= 0:
        return
    key = (guild.id, actor_id, action_name)
    cache = nuke_cache[key]
    current = utc_now().timestamp()
    cache.append(current)
    window = max(3, int(cfg.get("nuke_window", 10) or 10))
    while cache and current - cache[0] > window:
        cache.popleft()
    if len(cache) < threshold:
        return
    trigger_key = (guild.id, actor_id, action_name)
    if trigger_key in nuke_triggered:
        return
    nuke_triggered.add(trigger_key)
    cache.clear()
    banned = await neutralize_actor(
        guild,
        actor_id,
        reason=f"Exceeded {action_name} security threshold ({threshold} actions in {window}s)",
        source=action_name,
    )
    action_label = action_name.replace("_", " ").title()
    protection = "Security action completed." if banned else "Security action requires manual review."
    if not banned:
        nuke_triggered.discard(trigger_key)
    else:
        # FIX: allow future detection after cooldown instead of permanent block
        schedule_nuke_reset(trigger_key, delay=window*6)
    await send_log(
        guild,
        "🛡 Security Protection Activated",
        f"Suspicious **{action_label}** activity was detected.\n"
        f"Threshold: **{threshold} actions / {window} seconds**\n"
        f"{protection}",
        color=discord.Color.red() if banned else discord.Color.orange(),
    )


async def process_audit_event(guild: discord.Guild, action_name: str, audit_action, *, target_id=None, details=""):
    cfg = get_config(guild.id)
    if not cfg.get("server_active", False) or not cfg.get("antinuke", True):
        return
    lock_key = (guild.id, action_name, int(target_id or 0))
    async with audit_event_locks[lock_key]:
        await asyncio.sleep(0.75)
        entry = await latest_audit_entry(
            guild,
            audit_action,
            target_id=target_id,
            window=max(5, int(cfg.get("nuke_window", 10))),
        )
        if entry is None or entry.user_id is None:
            return
        seen_audit_entries.append(entry.id)
        await record_nuke_action(
            guild,
            int(entry.user_id),
            action_name,
            target=entry.target,
            details=details or f"Target: `{getattr(entry.target, 'id', 'unknown')}`",
        )


# ------------------------- Ready / Join ----------------------
@bot.event
async def on_ready():
    if TEST_GUILD_ID:
        guild = discord.Object(id=TEST_GUILD_ID)
        bot.tree.copy_global_to(guild=guild)
        synced = await bot.tree.sync(guild=guild)
        scope = f"test guild {TEST_GUILD_ID}"
    else:
        synced = await bot.tree.sync()
        scope = "global"
    print(f"Logged in as {bot.user} ({bot.user.id})")
    print(f"Synced {len(synced)} slash commands ({scope}).")
    print("Professional Mod Bot is online.")
    for guild in bot.guilds:
        me = guild.me
        if me and not me.guild_permissions.view_audit_log:
            print(f"WARNING: {guild.name}: View Audit Log permission is OFF. Anti-Nuke will be limited.")
        if me and not me.guild_permissions.ban_members:
            print(f"WARNING: {guild.name}: Ban Members permission is OFF. Anti-Nuke cannot ban attackers.")


@bot.event
async def on_guild_join(guild: discord.Guild):
    get_config(guild.id)
    save_data()


# ------------------------- Rejoin Protection -----------------
@bot.event
async def on_member_remove(member: discord.Member):
    if member.bot:
        return
    cfg = get_config(member.guild.id)
    if not cfg.get("server_active", False):
        return
    if not cfg.get("rejoin_protection", True):
        return
    cfg.setdefault("left_members", {})[str(member.id)] = {
        "username": str(member),
        "left_at": now_text(),
        "rejoin_dm_sent": False,
        "rejoin_blocked": False,
    }
    save_data()
    entry = await latest_audit_entry(
        member.guild,
        discord.AuditLogAction.kick,
        target_id=member.id,
        window=8,
    )
    if entry and entry.user_id:
        seen_audit_entries.append(entry.id)
        await record_nuke_action(
            member.guild,
            int(entry.user_id),
            "kick",
            details=f"Kicked member: `{member.id}`",
        )


@bot.event
async def on_member_join(member: discord.Member):
    cfg = get_config(member.guild.id)
    if not cfg.get("server_active", False):
        return
    if cfg.get("anti_raid", True):
        key = member.guild.id
        now_ts = utc_now().timestamp()
        joins = raid_cache[key]
        joins.append(now_ts)
        window = max(3, int(cfg.get("raid_window", 10) or 10))
        while joins and now_ts - joins[0] > window:
            joins.popleft()
        threshold = int(cfg.get("raid_threshold", 8) or 8)
        if len(joins) >= threshold:
            await send_log(
                member.guild,
                "🚨 Possible Raid Burst",
                f"**{len(joins)}** joins detected in `{window}s`.\nNew member: {fmt_member(member)}",
                color=discord.Color.red(),
            )
    left_members = cfg.setdefault("left_members", {})
    rejoin_key = (member.guild.id, member.id)
    left_key = str(member.id)
    if cfg.get("rejoin_protection", True) and left_key in left_members:
        async with rejoin_locks[rejoin_key]:
            record = left_members.get(left_key) or {}
            dm_sent = bool(record.get("rejoin_dm_sent", False))
            blocked = bool(record.get("rejoin_blocked", False))
            if rejoin_key in rejoin_handling:
                return
            rejoin_handling.add(rejoin_key)
            try:
                if not dm_sent:
                    record["rejoin_dm_sent"] = True
                    record["rejoin_blocked"] = False
                    record["last_attempt_at"] = now_text()
                    left_members[left_key] = record
                    save_data()
                    dm_text = (
                        f"🔨 You have been banned from **{member.guild.name}** for breaking server rules **(Rejoin)**!\n"
                        f"Contact with **{REJOIN_CONTACT}** or **{REJOIN_CONTACT_2}** to unban 🔰"
                    )
                    # FIX: send as embed with image so link text doesn't show
                    dm_embed = discord.Embed(
                        description=dm_text,
                        color=discord.Color.red()
                    )
                    dm_embed.set_image(url="https://media.tenor.com/znx_AntI870AAAAe/gorilla-middle-finger.png")
                    try:
                        await member.send(embed=dm_embed)
                    except:
                        await try_dm(member, dm_text)
                if blocked:
                    return
                me = member.guild.me
                if me and member.top_role < me.top_role:
                    try:
                        await member.ban(
                            reason="Rejoin Protection: member previously left and attempted to rejoin",
                            delete_message_seconds=0,
                        )
                        cfg["security_events"] = int(cfg.get("security_events", 0)) + 1
                        record["rejoin_blocked"] = True
                        record["blocked_at"] = now_text()
                        left_members[left_key] = record
                        save_data()
                        await send_log(
                            member.guild,
                            "⛔ Rejoin Protection",
                            "A returning member was automatically blocked because they had previously left the server.",
                            color=discord.Color.dark_red(),
                        )
                    except (discord.Forbidden, discord.HTTPException):
                        await send_log(
                            member.guild,
                            "⚠ Rejoin Protection",
                            "A returning member matched the protection rule, but Discord did not allow the automatic ban.",
                            color=discord.Color.orange(),
                        )
            finally:
                rejoin_handling.discard(rejoin_key)
    if member.bot and cfg.get("antinuke", True):
        await asyncio.sleep(0.65)
        entry = await latest_audit_entry(
            member.guild,
            discord.AuditLogAction.bot_add,
            target_id=member.id,
            window=max(5, int(cfg.get("nuke_window", 10))),
        )
        if entry and entry.user_id:
            seen_audit_entries.append(entry.id)
            actor_id = int(entry.user_id)
            await record_nuke_action(
                member.guild,
                actor_id,
                "bot_add",
                details=f"Added bot: `{member.id}`",
            )
            if not is_protected(member.guild, actor_id):
                try:
                    await member.ban(reason="Anti-Nuke: unauthorized bot added", delete_message_seconds=0)
                except (discord.Forbidden, discord.HTTPException):
                    pass


# ------------------------- AutoMod ---------------------------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return
    cfg = get_config(message.guild.id)
    if not cfg.get("server_active", False):
        return
    member = message.author
    if isinstance(member, discord.Member) and member.guild_permissions.manage_messages:
        return
    content = message.content or ""
    lower = content.lower()
    if cfg.get("anti_image", False) and message_has_image(message):
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        await send_log(
            message.guild,
            "🖼 AutoMod • Image Removed",
            f"User: {fmt_member(member)}\nChannel: {message.channel.mention}\nReason: Images/media are disabled here.",
            color=discord.Color.orange(),
        )
        return
    if cfg.get("anti_invite", True) and re.search(r"(?:discord(?:app)?\.com/invite/|discord\.gg/)[^\s]+", lower):
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        await add_warning(message.guild, member, member.id, "Automatic moderation: Discord invite link")
        await send_log(
            message.guild,
            "🔗 AutoMod • Invite Removed",
            f"User: {fmt_member(member)}\nChannel: {message.channel.mention}",
            color=discord.Color.orange(),
        )
        return
    if cfg.get("anti_links", False) and re.search(r"https?://\S+", lower):
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        await add_warning(message.guild, member, member.id, "Automatic moderation: external link")
        await send_log(
            message.guild,
            "🌐 AutoMod • Link Removed",
            f"User: {fmt_member(member)}\nChannel: {message.channel.mention}",
            color=discord.Color.orange(),
        )
        return
    bad_words = [w.lower() for w in cfg.get("bad_words", []) if w]
    if bad_words and any(re.search(rf"(?<!\w){re.escape(word)}(?!\w)", lower) for word in bad_words):
        try:
            await message.delete()
        except discord.HTTPException:
            pass
        await add_warning(message.guild, member, member.id, "Automatic moderation: filtered word")
        await send_log(
            message.guild,
            "🚫 AutoMod • Filtered Message",
            f"User: {fmt_member(member)}\nChannel: {message.channel.mention}",
            color=discord.Color.red(),
        )
        return
    if cfg.get("anticaps", False):
        letters = [c for c in content if c.isalpha()]
        if len(letters) >= 12:
            upper_ratio = sum(c.isupper() for c in letters) / len(letters)
            if upper_ratio >= 0.80:
                try:
                    await message.delete()
                except discord.HTTPException:
                    pass
                await add_warning(message.guild, member, member.id, "Automatic moderation: excessive caps")
                await send_log(
                    message.guild,
                    "🔠 AutoMod • Caps Removed",
                    f"User: {fmt_member(member)}\nChannel: {message.channel.mention}",
                    color=discord.Color.orange(),
                )
                return
    if cfg.get("anti_media_spam", True) and message_has_image(message):
        key = (message.guild.id, message.channel.id, member.id)
        timestamps = media_cache[key]
        now_ts = utc_now().timestamp()
        timestamps.append(now_ts)
        recent = [t for t in timestamps if now_ts - t <= 8]
        if len(recent) >= 4:
            timestamps.clear()
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            try:
                await member.timeout(timedelta(minutes=1), reason="AutoMod: media spam")
            except (discord.Forbidden, discord.HTTPException):
                pass
            await send_log(
                message.guild,
                "🖼 AutoMod • Media Spam Detected",
                f"User: {fmt_member(member)}\nChannel: {message.channel.mention}\nAction: Message removed; 1-minute timeout attempted.",
                color=discord.Color.red(),
            )
            return
    if cfg.get("antispam", True):
        key = (message.guild.id, message.channel.id, member.id)
        timestamps = spam_cache[key]
        now_ts = utc_now().timestamp()
        timestamps.append(now_ts)
        window = max(1, int(cfg.get("spam_window", 7)))
        threshold = max(2, int(cfg.get("spam_threshold", 6)))
        timeout_minutes = max(0, int(cfg.get("spam_timeout_minutes", 1)))
        recent = [t for t in timestamps if now_ts - t <= window]
        if len(recent) >= threshold:
            timestamps.clear()
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            if timeout_minutes > 0:
                try:
                    await member.timeout(timedelta(minutes=timeout_minutes), reason="AutoMod: spam")
                    action = f"Message removed and user timed out for {timeout_minutes} minute{'s' if timeout_minutes != 1 else ''}."
                except (discord.Forbidden, discord.HTTPException):
                    action = "Message removed; timeout could not be applied."
            else:
                action = "Message removed; spam timeout is disabled."
            await add_warning(message.guild, member, member.id, "Automatic moderation: spam")
            await send_log(
                message.guild,
                "🚨 AutoMod • Spam Detected",
                f"User: {fmt_member(member)}\nChannel: {message.channel.mention}\nRule: {threshold} messages / {window} seconds\nAction: {action}",
                color=discord.Color.red(),
            )
            return


# ------------------------- Anti-Nuke Events ------------------
@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    await process_audit_event(guild, "ban", discord.AuditLogAction.ban, target_id=user.id, details=f"Banned user: `{user.id}`")


@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    await process_audit_event(channel.guild, "channel_create", discord.AuditLogAction.channel_create, target_id=channel.id, details=f"Created channel: `{channel.name}` (`{channel.id}`)")


@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    await process_audit_event(channel.guild, "channel_delete", discord.AuditLogAction.channel_delete, target_id=channel.id, details=f"Deleted channel: `{channel.name}` (`{channel.id}`)")


@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    await process_audit_event(after.guild, "channel_update", discord.AuditLogAction.channel_update, target_id=after.id, details=f"Updated channel: `{after.name}` (`{after.id}`)")


@bot.event
async def on_guild_role_create(role: discord.Role):
    await process_audit_event(role.guild, "role_create", discord.AuditLogAction.role_create, target_id=role.id, details=f"Created role: `{role.name}` (`{role.id}`)")


@bot.event
async def on_guild_role_delete(role: discord.Role):
    await process_audit_event(role.guild, "role_delete", discord.AuditLogAction.role_delete, target_id=role.id, details=f"Deleted role: `{role.name}` (`{role.id}`)")


@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    await process_audit_event(after.guild, "role_update", discord.AuditLogAction.role_update, target_id=after.id, details=f"Updated role: `{after.name}` (`{after.id}`)")


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    if before.roles == after.roles:
        return
    await process_audit_event(after.guild, "member_role_update", discord.AuditLogAction.member_role_update, target_id=after.id, details=f"Role change on member: `{after.id}`")


@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    await process_audit_event(after, "guild_update", discord.AuditLogAction.guild_update, target_id=after.id, details="Server settings changed.")


@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    guild = channel.guild
    cfg = get_config(guild.id)
    if not cfg.get("server_active", False) or not cfg.get("antinuke", True):
        return
    async with webhook_scan_lock[guild.id]:
        await asyncio.sleep(0.65)
        candidates = []
        for action in (discord.AuditLogAction.webhook_create, discord.AuditLogAction.webhook_update, discord.AuditLogAction.webhook_delete):
            try:
                async for entry in guild.audit_logs(limit=5, action=action):
                    if entry.user_id is None or entry.id in seen_audit_entries:
                        continue
                    if (utc_now() - entry.created_at).total_seconds() > max(5, int(cfg.get("nuke_window", 10))):
                        continue
                    target_id = getattr(entry.target, "channel_id", None)
                    if target_id is None:
                        target_id = getattr(entry.target, "id", None)
                    if target_id == channel.id or target_id is None:
                        candidates.append(entry)
                        break
            except (discord.Forbidden, discord.HTTPException):
                continue
        if not candidates:
            return
        entry = max(candidates, key=lambda x: x.created_at)
        seen_audit_entries.append(entry.id)
        name_map = {
            discord.AuditLogAction.webhook_create: "webhook_create",
            discord.AuditLogAction.webhook_update: "webhook_update",
            discord.AuditLogAction.webhook_delete: "webhook_delete",
        }
        await record_nuke_action(guild, int(entry.user_id), name_map.get(entry.action, "webhook_update"), details=f"Webhook event in channel: {channel.mention}")


# ------------------------- Commands (same as before) -------------------------
@bot.tree.command(name="help", description="Show moderation and security commands")
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(title="🛡 Professional Mod Bot", color=discord.Color.blurple())
    embed.add_field(name="Moderation", value="` /warn` `/warnings` `/clear` `/kick` `/ban` `/unban`\n`/timeout` `/untimeout` `/nickname` `/role-add` `/role-remove`", inline=False)
    embed.add_field(name="Server / AutoMod", value="`/activate-server` `/deactivate-server` `/server-status`\n`/automod` `/set-antispam` `/add-badword` `/remove-badword`\n`/lock` `/unlock` `/slowmode` `/say`", inline=False)
    embed.add_field(name="Security", value="`/antinuke` `/rejoin-protection` `/anti-raid`\n`/protect-user` `/unprotect-user` `/protect-role`\n`/rejoin-clear` `/security`", inline=False)
    embed.add_field(name="Logging", value="`/set-log-channel` `/config`", inline=False)
    embed.set_footer(text="Role hierarchy and Discord permissions are enforced.")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="config", description="Show this server's moderation configuration")
@app_commands.checks.has_permissions(manage_guild=True)
async def config_command(interaction: discord.Interaction):
    cfg = get_config(interaction.guild.id)
    log = interaction.guild.get_channel(int(cfg.get("log_channel", 0) or 0))
    embed = discord.Embed(title="⚙ Server Configuration", color=discord.Color.blurple())
    embed.add_field(name="Server Status", value="🟢 ACTIVE" if cfg.get("server_active") else "🔴 INACTIVE", inline=False)
    embed.add_field(name="Log channel", value=log.mention if log else "Not set", inline=True)
    embed.add_field(name="Anti-spam", value="ON" if cfg.get("antispam") else "OFF", inline=True)
    embed.add_field(name="Spam rule", value=f"{int(cfg.get('spam_threshold', 6))} messages / {int(cfg.get('spam_window', 7))} seconds | timeout: {int(cfg.get('spam_timeout_minutes', 1))} min", inline=False)
    embed.add_field(name="Anti-invite", value="ON" if cfg.get("anti_invite") else "OFF", inline=True)
    embed.add_field(name="Anti-links", value="ON" if cfg.get("anti_links") else "OFF", inline=True)
    embed.add_field(name="Anti-caps", value="ON" if cfg.get("anticaps") else "OFF", inline=True)
    embed.add_field(name="Anti-image", value="ON" if cfg.get("anti_image") else "OFF", inline=True)
    embed.add_field(name="Anti-Nuke", value="ON" if cfg.get("antinuke") else "OFF", inline=True)
    embed.add_field(name="Rejoin protection", value="ON" if cfg.get("rejoin_protection") else "OFF", inline=True)
    embed.add_field(name="Anti-raid", value="ON" if cfg.get("anti_raid") else "OFF", inline=True)
    embed.add_field(name="Protected users", value=str(len(cfg.get("protected_users", []))), inline=True)
    embed.add_field(name="Remembered leavers", value=str(len(cfg.get("left_members", {}))), inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="security", description="Show Anti-Nuke and security status")
@app_commands.checks.has_permissions(manage_guild=True)
async def security_command(interaction: discord.Interaction):
    cfg = get_config(interaction.guild.id)
    thresholds = cfg.get("nuke_thresholds", {})
    threshold_text = "\n".join(f"• `{name}` → **{value}** / {cfg.get('nuke_window', 10)}s" for name, value in thresholds.items())
    embed = discord.Embed(title="🛡 Security Center", color=discord.Color.dark_teal())
    embed.add_field(name="Anti-Nuke", value="🟢 ON" if cfg.get("antinuke") else "🔴 OFF", inline=True)
    embed.add_field(name="Rejoin protection", value="🟢 ON" if cfg.get("rejoin_protection") else "🔴 OFF", inline=True)
    embed.add_field(name="Anti-Raid", value="🟢 ON" if cfg.get("anti_raid") else "🔴 OFF", inline=True)
    embed.add_field(name="Protected users", value=str(len(cfg.get("protected_users", []))), inline=True)
    embed.add_field(name="Protected roles", value=str(len(cfg.get("protected_roles", []))), inline=True)
    embed.add_field(name="Nuke thresholds", value=threshold_text[:1024], inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="say", description="Make the bot send a message in this channel")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(message="The message the bot should send")
async def say_command(interaction: discord.Interaction, message: str):
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.response.send_message("❌ This command only works in a text channel.", ephemeral=True)
        return
    message = message.strip()
    if not message:
        await interaction.response.send_message("❌ Message cannot be empty.", ephemeral=True)
        return
    if len(message) > 2000:
        await interaction.response.send_message("❌ Discord messages can be up to 2000 characters.", ephemeral=True)
        return
    try:
        await interaction.channel.send(message)
        await interaction.response.send_message("✅ Message sent.", ephemeral=True)
    except discord.Forbidden:
        await interaction.response.send_message("❌ I cannot send messages in this channel.", ephemeral=True)
    except discord.HTTPException:
        await interaction.response.send_message("❌ Discord could not send the message.", ephemeral=True)


@bot.tree.command(name="activate-server", description="Activate all moderation and security systems for this server using Server ID")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(server_id="The Discord Server ID")
async def activate_server(interaction: discord.Interaction, server_id: str):
    try:
        sid = int(server_id)
    except ValueError:
        await interaction.response.send_message("❌ Server ID must be a number.", ephemeral=True)
        return
    if sid != interaction.guild.id:
        await interaction.response.send_message("❌ For security, the Server ID must match the server where you run this command.", ephemeral=True)
        return
    cfg = get_config(sid)
    cfg["server_active"] = True
    save_data()
    await interaction.response.send_message(f"✅ **{interaction.guild.name}** is now **ACTIVE**.", ephemeral=True)
    await send_log(interaction.guild, "🟢 SERVER ACTIVATED", f"Server: **{interaction.guild.name}** (`{sid}`)", color=discord.Color.green())


@bot.tree.command(name="deactivate-server", description="Deactivate all automatic moderation and security systems for this server")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(server_id="The Discord Server ID")
async def deactivate_server(interaction: discord.Interaction, server_id: str):
    try:
        sid = int(server_id)
    except ValueError:
        await interaction.response.send_message("❌ Server ID must be a number.", ephemeral=True)
        return
    if sid != interaction.guild.id:
        await interaction.response.send_message("❌ For security, the Server ID must match the server where you run this command.", ephemeral=True)
        return
    cfg = get_config(sid)
    cfg["server_active"] = False
    save_data()
    await interaction.response.send_message(f"🟠 **{interaction.guild.name}** is now **INACTIVE**.", ephemeral=True)
    await send_log(interaction.guild, "🟠 SERVER DEACTIVATED", f"Server: **{interaction.guild.name}** (`{sid}`)", color=discord.Color.orange())


@bot.tree.command(name="server-status", description="Show whether this server's automatic protection is active")
@app_commands.checks.has_permissions(manage_guild=True)
async def server_status(interaction: discord.Interaction):
    cfg = get_config(interaction.guild.id)
    status = "🟢 ACTIVE" if cfg.get("server_active") else "🔴 INACTIVE"
    await interaction.response.send_message(f"**{interaction.guild.name}** — {status}\nServer ID: `{interaction.guild.id}`", ephemeral=True)


@bot.tree.command(name="set-log-channel", description="Set the moderation log channel using Channel ID")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(channel_id="The Discord Channel ID")
async def set_log_channel(interaction: discord.Interaction, channel_id: str):
    try:
        cid = int(channel_id)
    except ValueError:
        await interaction.response.send_message("❌ Channel ID must be a number.", ephemeral=True)
        return
    channel = interaction.guild.get_channel(cid)
    if channel is None or not isinstance(channel, discord.TextChannel):
        await interaction.response.send_message("❌ That ID is not a text channel in this server.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    cfg["log_channel"] = cid
    save_data()
    await interaction.response.send_message(f"✅ Moderation and security logs will go to {channel.mention}.", ephemeral=True)


@bot.tree.command(name="automod", description="Turn AutoMod features on or off")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(feature="Feature name", state="on or off")
@app_commands.choices(feature=[
    app_commands.Choice(name="anti-spam", value="antispam"),
    app_commands.Choice(name="anti-invite", value="anti_invite"),
    app_commands.Choice(name="anti-links", value="anti_links"),
    app_commands.Choice(name="anti-caps", value="anticaps"),
    app_commands.Choice(name="anti-image", value="anti_image"),
    app_commands.Choice(name="anti-media-spam", value="anti_media_spam"),
])
async def automod_command(interaction: discord.Interaction, feature: app_commands.Choice[str], state: str):
    enabled = parse_on_off(state)
    if enabled is None:
        await interaction.response.send_message("❌ State must be `on` or `off`.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    cfg[feature.value] = enabled
    save_data()
    await interaction.response.send_message(f"✅ `{feature.name}` is now **{'ON' if enabled else 'OFF'}**.", ephemeral=True)


@bot.tree.command(name="set-antispam", description="Set Anti-Spam message count, timing window, and timeout")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(messages="How many messages trigger Anti-Spam", seconds="Time window in seconds", timeout_minutes="Timeout duration after spam; use 0 to disable timeout")
async def set_antispam_command(interaction: discord.Interaction, messages: app_commands.Range[int, 2, 100], seconds: app_commands.Range[int, 1, 120], timeout_minutes: app_commands.Range[int, 0, 10080] = 1):
    cfg = get_config(interaction.guild.id)
    cfg["spam_threshold"] = int(messages)
    cfg["spam_window"] = int(seconds)
    cfg["spam_timeout_minutes"] = int(timeout_minutes)
    save_data()
    timeout_text = f"{timeout_minutes} minute{'s' if timeout_minutes != 1 else ''}" if timeout_minutes > 0 else "disabled"
    await interaction.response.send_message(f"✅ Anti-Spam updated: **{messages} messages / {seconds} seconds**, timeout: **{timeout_text}**.", ephemeral=True)


@bot.tree.command(name="antinuke", description="Turn Anti-Nuke protection on or off")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(state="on or off")
async def antinuke_command(interaction: discord.Interaction, state: str):
    enabled = parse_on_off(state)
    if enabled is None:
        await interaction.response.send_message("❌ State must be `on` or `off`.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    cfg["antinuke"] = enabled
    save_data()
    await interaction.response.send_message(f"🛡 Anti-Nuke is now **{'ON' if enabled else 'OFF'}**.", ephemeral=True)


@bot.tree.command(name="rejoin-protection", description="Auto-ban users who leave and later try to rejoin")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(state="on or off")
async def rejoin_protection_command(interaction: discord.Interaction, state: str):
    enabled = parse_on_off(state)
    if enabled is None:
        await interaction.response.send_message("❌ State must be `on` or `off`.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    cfg["rejoin_protection"] = enabled
    save_data()
    await interaction.response.send_message(f"🔁 Rejoin Protection is now **{'ON' if enabled else 'OFF'}**.", ephemeral=True)


@bot.tree.command(name="anti-raid", description="Turn join-burst Anti-Raid protection on or off")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(state="on or off")
async def anti_raid_command(interaction: discord.Interaction, state: str):
    enabled = parse_on_off(state)
    if enabled is None:
        await interaction.response.send_message("❌ State must be `on` or `off`.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    cfg["anti_raid"] = enabled
    save_data()
    await interaction.response.send_message(f"🚨 Anti-Raid is now **{'ON' if enabled else 'OFF'}**.", ephemeral=True)


@bot.tree.command(name="protect-user", description="Protect a user from Anti-Nuke actions")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(user_id="Discord User ID")
async def protect_user(interaction: discord.Interaction, user_id: str):
    try:
        uid = int(user_id)
    except ValueError:
        await interaction.response.send_message("❌ User ID must be a number.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    if uid not in cfg["protected_users"]:
        cfg["protected_users"].append(uid)
        save_data()
    await interaction.response.send_message(f"✅ Protected user `{uid}`.", ephemeral=True)


@bot.tree.command(name="unprotect-user", description="Remove a user from Anti-Nuke protection")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(user_id="Discord User ID")
async def unprotect_user(interaction: discord.Interaction, user_id: str):
    try:
        uid = int(user_id)
    except ValueError:
        await interaction.response.send_message("❌ User ID must be a number.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    if uid in cfg["protected_users"]:
        cfg["protected_users"].remove(uid)
        save_data()
    await interaction.response.send_message(f"✅ Removed Anti-Nuke protection from `{uid}`.", ephemeral=True)


@bot.tree.command(name="protect-role", description="Protect every member who has this role from Anti-Nuke")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(role="Role to protect")
async def protect_role(interaction: discord.Interaction, role: discord.Role):
    cfg = get_config(interaction.guild.id)
    if role.id not in cfg["protected_roles"]:
        cfg["protected_roles"].append(role.id)
        save_data()
    await interaction.response.send_message(f"✅ Protected role {role.mention}.", ephemeral=True)


@bot.tree.command(name="unprotect-role", description="Remove a role from Anti-Nuke protection")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(role="Role to unprotect")
async def unprotect_role(interaction: discord.Interaction, role: discord.Role):
    cfg = get_config(interaction.guild.id)
    if role.id in cfg["protected_roles"]:
        cfg["protected_roles"].remove(role.id)
        save_data()
    await interaction.response.send_message(f"✅ Removed protection from {role.mention}.", ephemeral=True)


@bot.tree.command(name="rejoin-clear", description="Allow a previously departed user to rejoin normally")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(user_id="Discord User ID")
async def rejoin_clear(interaction: discord.Interaction, user_id: str):
    try:
        uid = int(user_id)
    except ValueError:
        await interaction.response.send_message("❌ User ID must be a number.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    removed = cfg.setdefault("left_members", {}).pop(str(uid), None)
    save_data()
    if removed:
        await interaction.response.send_message(f"✅ Rejoin protection cleared for `{uid}`.", ephemeral=True)
    else:
        await interaction.response.send_message(f"ℹ No rejoin protection record exists for `{uid}`.", ephemeral=True)


# Moderation commands - same as original, omitted for brevity but included in full file
@bot.tree.command(name="warn", description="Warn a member")
@app_commands.checks.has_permissions(manage_messages=True)
@app_commands.describe(member="Member to warn", reason="Reason for the warning")
async def warn_command(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    ok, msg = can_moderate(interaction.user, member)
    if not ok:
        await interaction.response.send_message(f"❌ {msg}", ephemeral=True)
        return
    reason = clean_reason(reason)
    await add_warning(interaction.guild, member, interaction.user.id, reason)
    count = len(get_config(interaction.guild.id)["warnings"].get(str(member.id), []))
    await try_dm(member, f"⚠ You were warned in **{interaction.guild.name}**.\nReason: {reason}")
    await interaction.response.send_message(f"✅ Warned {member.mention}. Total warnings: **{count}**.")
    await send_log(interaction.guild, "⚠ Member Warned", f"Member: {fmt_member(member)}\nReason: {reason}", color=discord.Color.orange())


@bot.tree.command(name="warnings", description="Show a member's warnings")
@app_commands.checks.has_permissions(manage_messages=True)
@app_commands.describe(member="Member whose warnings you want to view")
async def warnings_command(interaction: discord.Interaction, member: discord.Member):
    cfg = get_config(interaction.guild.id)
    entries = cfg.get("warnings", {}).get(str(member.id), [])
    if not entries:
        await interaction.response.send_message(f"ℹ {member.mention} has no warnings.", ephemeral=True)
        return
    lines = []
    for i, entry in enumerate(entries[-10:], 1):
        mod = interaction.guild.get_member(int(entry.get("moderator_id", 0)))
        mod_text = mod.mention if mod else f"`{entry.get('moderator_id', 'Unknown')}`"
        lines.append(f"**{i}.** {entry.get('reason', 'No reason')} — by {mod_text} — {entry.get('time', '')}")
    embed = discord.Embed(title=f"⚠ Warnings • {member}", description="\n".join(lines), color=discord.Color.orange())
    embed.set_footer(text=f"Total warnings: {len(entries)}")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="clear", description="Delete recent messages")
@app_commands.checks.has_permissions(manage_messages=True)
@app_commands.describe(amount="Number of messages to delete (1-100)")
async def clear_command(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]):
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.response.send_message("❌ This only works in text channels.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    deleted = await interaction.channel.purge(limit=amount)
    await interaction.followup.send(f"✅ Deleted **{len(deleted)}** messages.", ephemeral=True)


@bot.tree.command(name="kick", description="Kick a member")
@app_commands.checks.has_permissions(kick_members=True)
@app_commands.describe(member="Member to kick", reason="Reason for the kick")
async def kick_command(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    ok, msg = can_moderate(interaction.user, member)
    if not ok:
        await interaction.response.send_message(f"❌ {msg}", ephemeral=True)
        return
    reason = clean_reason(reason)
    await try_dm(member, f"👢 You were kicked from **{interaction.guild.name}**.\nReason: {reason}")
    await member.kick(reason=reason)
    await interaction.response.send_message(f"✅ Kicked {member.mention}.")


@bot.tree.command(name="ban", description="Ban a user by User ID")
@app_commands.checks.has_permissions(ban_members=True)
@app_commands.describe(user_id="Discord User ID", reason="Reason for the ban")
async def ban_command(interaction: discord.Interaction, user_id: str, reason: str = "No reason provided"):
    try:
        uid = int(user_id)
    except ValueError:
        await interaction.response.send_message("❌ User ID must be a number.", ephemeral=True)
        return
    member = interaction.guild.get_member(uid)
    if member is not None:
        ok, msg = can_moderate(interaction.user, member)
        if not ok:
            await interaction.response.send_message(f"❌ {msg}", ephemeral=True)
            return
        target = member
    else:
        try:
            target = await bot.fetch_user(uid)
        except discord.NotFound:
            await interaction.response.send_message("❌ User ID is invalid or the user could not be found.", ephemeral=True)
            return
    reason = clean_reason(reason)
    await try_dm(target, f"🔨 You were banned from **{interaction.guild.name}**.\nReason: {reason}")
    try:
        await interaction.guild.ban(target, reason=reason, delete_message_seconds=0)
    except discord.Forbidden:
        await interaction.response.send_message("❌ Discord refused the ban. Check my Ban Members permission and role hierarchy.", ephemeral=True)
        return
    mention = member.mention if member is not None else f"<@{uid}>"
    await interaction.response.send_message(f"✅ Banned {mention} (`{uid}`).")


@bot.tree.command(name="unban", description="Unban a user by User ID")
@app_commands.checks.has_permissions(ban_members=True)
@app_commands.describe(user_id="Discord User ID", reason="Reason for the unban")
async def unban_command(interaction: discord.Interaction, user_id: str, reason: str = "No reason provided"):
    try:
        uid = int(user_id)
    except ValueError:
        await interaction.response.send_message("❌ User ID must be a number.", ephemeral=True)
        return
    try:
        user = await bot.fetch_user(uid)
        await interaction.guild.unban(user, reason=clean_reason(reason))
    except discord.NotFound:
        await interaction.response.send_message("❌ User is not banned or the user ID is invalid.", ephemeral=True)
        return
    await interaction.response.send_message(f"✅ Unbanned **{user}** (`{user.id}`).")


@bot.tree.command(name="timeout", description="Timeout a member")
@app_commands.checks.has_permissions(moderate_members=True)
@app_commands.describe(member="Member to timeout", minutes="Timeout duration in minutes (1-40320)", reason="Reason")
async def timeout_command(interaction: discord.Interaction, member: discord.Member, minutes: app_commands.Range[int, 1, 40320], reason: str = "No reason provided"):
    ok, msg = can_moderate(interaction.user, member)
    if not ok:
        await interaction.response.send_message(f"❌ {msg}", ephemeral=True)
        return
    reason = clean_reason(reason)
    await member.timeout(timedelta(minutes=minutes), reason=reason)
    await interaction.response.send_message(f"✅ Timed out {member.mention} for **{minutes} minutes**.")


@bot.tree.command(name="untimeout", description="Remove a member's timeout")
@app_commands.checks.has_permissions(moderate_members=True)
@app_commands.describe(member="Member whose timeout should be removed", reason="Reason")
async def untimeout_command(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    ok, msg = can_moderate(interaction.user, member)
    if not ok:
        await interaction.response.send_message(f"❌ {msg}", ephemeral=True)
        return
    await member.timeout(None, reason=clean_reason(reason))
    await interaction.response.send_message(f"✅ Removed timeout from {member.mention}.")


@bot.tree.command(name="nickname", description="Change or remove a member's nickname")
@app_commands.checks.has_permissions(manage_nicknames=True)
@app_commands.describe(member="Member", nickname="New nickname; leave blank to reset")
async def nickname_command(interaction: discord.Interaction, member: discord.Member, nickname: Optional[str] = None):
    ok, msg = can_moderate(interaction.user, member)
    if not ok:
        await interaction.response.send_message(f"❌ {msg}", ephemeral=True)
        return
    if nickname is not None:
        nickname = nickname[:32]
    await member.edit(nick=nickname, reason=f"Nickname changed by {interaction.user}")
    await interaction.response.send_message(f"✅ Nickname updated for {member.mention}." if nickname else f"✅ Nickname reset for {member.mention}.")


@bot.tree.command(name="role-add", description="Add a role to a member")
@app_commands.checks.has_permissions(manage_roles=True)
@app_commands.describe(member="Member", role="Role to add")
async def role_add_command(interaction: discord.Interaction, member: discord.Member, role: discord.Role):
    if role.is_default():
        await interaction.response.send_message("❌ You cannot assign @everyone.", ephemeral=True)
        return
    if role >= interaction.guild.me.top_role:
        await interaction.response.send_message("❌ That role is higher than or equal to my highest role.", ephemeral=True)
        return
    await member.add_roles(role, reason=f"Role added by {interaction.user}")
    await interaction.response.send_message(f"✅ Added {role.mention} to {member.mention}.")


@bot.tree.command(name="role-remove", description="Remove a role from a member")
@app_commands.checks.has_permissions(manage_roles=True)
@app_commands.describe(member="Member", role="Role to remove")
async def role_remove_command(interaction: discord.Interaction, member: discord.Member, role: discord.Role):
    if role.is_default():
        await interaction.response.send_message("❌ You cannot remove @everyone.", ephemeral=True)
        return
    if role >= interaction.guild.me.top_role:
        await interaction.response.send_message("❌ That role is higher than or equal to my highest role.", ephemeral=True)
        return
    await member.remove_roles(role, reason=f"Role removed by {interaction.user}")
    await interaction.response.send_message(f"✅ Removed {role.mention} from {member.mention}.")


@bot.tree.command(name="lock", description="Lock this channel for normal members")
@app_commands.checks.has_permissions(manage_channels=True)
async def lock_command(interaction: discord.Interaction):
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.response.send_message("❌ This only works in text channels.", ephemeral=True)
        return
    await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=False, reason=f"Channel locked by {interaction.user}")
    await interaction.response.send_message("🔒 Channel locked.")


@bot.tree.command(name="unlock", description="Unlock this channel for normal members")
@app_commands.checks.has_permissions(manage_channels=True)
async def unlock_command(interaction: discord.Interaction):
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.response.send_message("❌ This only works in text channels.", ephemeral=True)
        return
    await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=None, reason=f"Channel unlocked by {interaction.user}")
    await interaction.response.send_message("🔓 Channel unlocked.")


@bot.tree.command(name="slowmode", description="Set channel slowmode")
@app_commands.checks.has_permissions(manage_channels=True)
@app_commands.describe(seconds="0-21600 seconds; 0 disables slowmode")
async def slowmode_command(interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 21600]):
    if not isinstance(interaction.channel, discord.TextChannel):
        await interaction.response.send_message("❌ This only works in text channels.", ephemeral=True)
        return
    await interaction.channel.edit(slowmode_delay=seconds, reason=f"Slowmode changed by {interaction.user}")
    await interaction.response.send_message(f"✅ Slowmode set to **{seconds} seconds**.")


@bot.tree.command(name="add-badword", description="Add a word to the AutoMod filter")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(word="Word to filter")
async def add_badword(interaction: discord.Interaction, word: str):
    word = word.strip().lower()
    if not word or len(word) > 50:
        await interaction.response.send_message("❌ Word must be 1-50 characters.", ephemeral=True)
        return
    cfg = get_config(interaction.guild.id)
    if word not in cfg["bad_words"]:
        cfg["bad_words"].append(word)
        save_data()
        await interaction.response.send_message(f"✅ Added `{word}` to the filter.", ephemeral=True)
    else:
        await interaction.response.send_message("ℹ That word is already in the filter.", ephemeral=True)


@bot.tree.command(name="remove-badword", description="Remove a word from the AutoMod filter")
@app_commands.checks.has_permissions(manage_guild=True)
@app_commands.describe(word="Word to remove")
async def remove_badword(interaction: discord.Interaction, word: str):
    word = word.strip().lower()
    cfg = get_config(interaction.guild.id)
    if word in cfg["bad_words"]:
        cfg["bad_words"].remove(word)
        save_data()
        await interaction.response.send_message(f"✅ Removed `{word}` from the filter.", ephemeral=True)
    else:
        await interaction.response.send_message("ℹ That word is not in the filter.", ephemeral=True)


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        perms = ", ".join(error.missing_permissions).replace("_", " ")
        message = f"❌ You do not have permission to use this command. Required: **{perms}**."
    elif isinstance(error, app_commands.CheckFailure):
        message = "❌ You do not have permission to use this command."
    elif isinstance(error, app_commands.CommandInvokeError):
        original = error.original
        if isinstance(original, discord.Forbidden):
            message = "❌ Discord refused the action. Check bot permissions and role hierarchy."
        elif isinstance(original, discord.HTTPException):
            message = f"❌ Discord API error: {original}"
        else:
            print("Command error:", repr(original))
            message = "❌ Something went wrong. Check the console."
    else:
        print("App command error:", repr(error))
        message = "❌ Something went wrong while executing the command."
    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass


# ---------------------- Render HTTP Health Server ----------------------
async def health_check(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Respond to Render and UptimeRobot HTTP checks."""
    try:
        await reader.readline()  # Request line
        while True:
            line = await reader.readline()
            if not line or line in (b"\\r\\n", b"\\n"):
                break

        body = b"Discord bot is running."
        response = (
            b"HTTP/1.1 200 OK\\r\\n"
            b"Content-Type: text/plain; charset=utf-8\\r\\n"
            + f"Content-Length: {len(body)}\\r\\n".encode("ascii")
            + b"Connection: close\\r\\n\\r\\n"
            + body
        )
        writer.write(response)
        await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, asyncio.CancelledError):
            pass


async def main():
    if not TOKEN or TOKEN == "PASTE_YOUR_BOT_TOKEN_HERE":
        raise SystemExit(
            "Set your Discord bot token in the DISCORD_TOKEN environment variable."
        )

    # Render supplies PORT automatically for Web Services.
    port = int(os.getenv("PORT", "10000"))
    server = await asyncio.start_server(
        health_check,
        host="0.0.0.0",
        port=port,
    )
    print(f"HTTP health server listening on 0.0.0.0:{port}")

    try:
        await bot.start(TOKEN)
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
