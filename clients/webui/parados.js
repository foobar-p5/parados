"use strict";

let items = [];
let active_id = null;

function $(id)
{
	return document.getElementById(id);
}

function status_set(s)
{
	const e = $("status");
	if (e)
		e.textContent = s;
}

function base_url()
{
	const e = $("base");
	const s = e ? (e.value || "") : "";
	return s.replace(/\/+$/, "");
}

function human_size(n)
{
	if (typeof n !== "number" || !isFinite(n))
		return "" + n;

	const u = ["B","KB","MB","GB","TB"];
	let i = 0;
	while (n >= 1024 && i < u.length - 1) {
		n /= 1024;
		i++;
	}
	return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + " " + u[i];
}

function is_video(type, path)
{
	if (type && type.startsWith("video/"))
		return true;

	return /\.(mp4|mkv|webm|mov)$/i.test(path || "");
}

function is_audio(type, path)
{
	if (type && type.startsWith("audio/"))
		return true;

	return /\.(mp3|m4a|aac|flac|wav|ogg|opus)$/i.test(path || "");
}

function clear_players()
{
	const a = $("aud");
	const v = $("vid");

	if (a) {
		a.pause();
		a.removeAttribute("src");
		a.style.display = "none";
	}
	if (v) {
		v.pause();
		v.removeAttribute("src");
		v.style.display = "none";
	}
}

async function api_json(url)
{
	const r = await fetch(url, { method: "GET" });
	if (!r.ok) {
		let t = "";
		try {
			t = await r.text();
		}
		catch (e) {
			t = "";
		}
		t = (t || "").trim();
		throw new Error("http " + r.status + (t ? (": " + t) : ""));
	}

	return await r.json();
}

function render_list()
{
	const list = $("list");
	const f = $("filter");

	if (!list)
		return;

	const q = (f ? (f.value || "") : "").toLowerCase();

	list.innerHTML = "";
	for (const it of items) {
		if (q && !(it.path || "").toLowerCase().includes(q))
			continue;

		const li = document.createElement("li");
		li.dataset.id = it.id;
		li.textContent = it.path || it.id;

		if (it.id === active_id)
			li.classList.add("active");

		li.addEventListener("click", () => select_item(it.id));

		list.appendChild(li);
	}
}

function set_active_class()
{
	const list = $("list");
	if (!list)
		return;

	const lis = list.querySelectorAll("li");
	for (const li of lis) {
		if (li.dataset.id === active_id)
			li.classList.add("active");
		else
			li.classList.remove("active");
	}
}

async function load_library()
{
	status_set("loading...");
	clear_players();

	const now = $("now");
	const meta = $("meta");

	if (now)
		now.textContent = "";
	if (meta)
		meta.textContent = "";

	const base = base_url();
	const j = await api_json(base + "/library");

	if (!j || !Array.isArray(j.items))
		throw new Error("bad /library json");

	items = j.items.slice();
	active_id = null;

	status_set("ok (" + items.length + " items)");
	render_list();
}

async function select_item(id)
{
	active_id = id;
	set_active_class();
	clear_players();

	const base = base_url();

	const it = items.find(x => x.id === id);
	const path = it ? (it.path || "") : "";

	const now = $("now");
	const meta = $("meta");
	const a = $("aud");
	const v = $("vid");

	if (now)
		now.textContent = path ? path : ("id " + id);
	if (meta)
		meta.textContent = "loading meta...";

	let m = null;
	try {
		m = await api_json(base + "/meta/" + id);
	}
	catch (e) {
		if (meta)
			meta.textContent = "" + e;
		return;
	}

	const type = m.type || "";
	const size = Number(m.size);

	if (meta) {
		meta.textContent =
			"id:   " + (m.id || id) + "\n" +
			"path: " + (m.path || path) + "\n" +
			"type: " + type + "\n" +
			"size: " + (isFinite(size) ? human_size(size) : (m.size || "")) + "\n";
	}

	const stream = base + "/stream/" + id;

	if (v && is_video(type, m.path || path)) {
		v.src = stream;
		v.style.display = "block";
		v.load();
		return;
	}

	if (a && is_audio(type, m.path || path)) {
		a.src = stream;
		a.style.display = "block";
		a.load();
		return;
	}

	if (meta)
		meta.textContent += "\n(no player for this type)\n";
}

async function main()
{
	const cfg = $("cfg");
	const load = $("load");
	const filter = $("filter");

	if (cfg) {
		cfg.addEventListener("submit", async (ev) => {
			ev.preventDefault();
			if (load)
				load.disabled = true;

			try {
				await load_library();
			}
			catch (e) {
				status_set("error: " + (e.message || e));
			}
			finally {
				if (load)
					load.disabled = false;
			}
		});
	}

	if (filter)
		filter.addEventListener("input", render_list);

	try {
		await load_library();
	}
	catch (e) {
		status_set("error: " + (e.message || e));
	}
}

main();

