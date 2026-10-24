export {};

const giscusOrigin = "https://giscus.app";
// Keep one client/iframe for the document: client.js installs a window message listener.
// Parking it outside Swup containers also prevents cached pages from retaining iframes.
const host = document.createElement("div");
host.id = "giscus-container";
host.className = "giscus";
let client: HTMLScriptElement | undefined;
let swapping = false;
let observedFrame: HTMLIFrameElement | undefined;

function theme(): string {
	return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

function syncTheme(): void {
	const frame = host.querySelector<HTMLIFrameElement>("iframe.giscus-frame");
	frame?.contentWindow?.postMessage(
		{ giscus: { setConfig: { theme: theme() } } },
		giscusOrigin,
	);
}

function park(): void {
	host.hidden = true;
	document.body.appendChild(host);
}

function mount(): void {
	const target = document.querySelector<HTMLElement>("[data-giscus-path]");
	if (swapping || !target) {
		if (client) park();
		return;
	}

	const path = target.dataset.giscusPath;
	if (!path) return;
	const frame = host.querySelector<HTMLIFrameElement>("iframe.giscus-frame");
	if (frame) {
		if (frame !== observedFrame) {
			observedFrame = frame;
			frame.addEventListener("load", () => {
				mount();
				syncTheme();
			});
		}
		const expectedTerm =
			path.length < 2 ? "index" : path.substring(1).replace(/\.\w+$/, "");
		const page = new URL(path, location.origin);
		const src = new URL(frame.src);
		if (
			src.searchParams.get("term") !== expectedTerm ||
			src.searchParams.get("origin") !== `${page.href}#${host.id}` ||
			src.searchParams.get("backLink") !== page.href
		) {
			// Preserve the official client's session/config, but refresh the page identity.
			// This follows client.ts's pathname mapping (including its leading-slash removal).
			src.searchParams.set("term", expectedTerm);
			src.searchParams.set("origin", `${page.href}#${host.id}`);
			src.searchParams.set("backLink", page.href);
			src.searchParams.set(
				"description",
				document.querySelector<HTMLMetaElement>(
					'meta[property="og:description"]',
				)?.content || "",
			);
			src.searchParams.set("theme", theme());
			if (src.href !== frame.src) frame.src = src.href;
		}
	}

	host.hidden = false;
	if (host.parentElement !== target) target.appendChild(host);
	if (client) return;

	client = document.createElement("script");
	client.src = `${giscusOrigin}/client.js`;
	client.async = true;
	client.crossOrigin = "anonymous";
	// Swup's scripts plugin otherwise re-executes even persistent body scripts.
	client.setAttribute("data-swup-ignore-script", "");
	const attributes = {
		repo: "Copper0SO4/copper0so4.github.io",
		"repo-id": "R_kgDOVVgLHA",
		category: "Announcements",
		"category-id": "DIC_kwDOVVgLHM4DJe6W",
		mapping: "pathname",
		strict: "1",
		"reactions-enabled": "1",
		"emit-metadata": "0",
		"input-position": "top",
		theme: theme(),
		lang: "zh-CN",
		loading: "lazy",
	};
	for (const [key, value] of Object.entries(attributes)) {
		client.setAttribute(`data-${key}`, value);
	}
	client.addEventListener(
		"load",
		() => {
			mount();
			syncTheme();
		},
		{ once: true },
	);
	client.addEventListener(
		"error",
		() => {
			client?.remove();
			client = undefined;
			const retry = document.createElement("button");
			retry.type = "button";
			retry.className = "btn-plain rounded-lg p-3";
			retry.textContent = "评论加载失败，点击重试";
			retry.addEventListener(
				"click",
				() => {
					host.replaceChildren();
					mount();
				},
				{ once: true },
			);
			host.replaceChildren(retry);
		},
		{ once: true },
	);
	// Keep the script outside the host: client.js replaces the host's children.
	document.body.appendChild(client);
}

// @swup/astro emits these events from content:replace and page:view.
document.addEventListener("astro:before-swap", () => {
	swapping = true;
	if (client) park();
});
document.addEventListener("astro:page-load", () => {
	swapping = false;
	mount();
});
new MutationObserver(syncTheme).observe(document.documentElement, {
	attributes: true,
	attributeFilter: ["class"],
});
if (document.readyState === "loading") {
	document.addEventListener("DOMContentLoaded", mount, { once: true });
} else {
	mount();
}
