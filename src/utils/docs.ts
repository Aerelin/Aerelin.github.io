import type { Document } from "astro-spaceship/types";

/** Windows 下主题用 path.join 生成 permalink，会把分隔符变成反斜杠，这里统一成 '/'。 */
export const normalizePath = (value = "") => value.replace(/\\/g, "/");

export const docUrl = (doc: Document) => {
  const path = normalizePath(doc.data.permalink);
  return path.startsWith("/") ? path : `/${path}`;
};

/** 从文章路径里取出所属目录（writeups / pwn-notes / blockchain）。 */
export const docFolder = (doc: Document) => {
  const filePath = normalizePath((doc as { filePath?: string }).filePath ?? "");
  const fromFile = filePath.match(/vault\/([^/]+)\//);
  if (fromFile) return fromFile[1];

  const segments = normalizePath(doc.data.permalink).replace(/^\/+/, "").split("/");
  return segments.length > 1 ? segments[0] : "writeups";
};

export const formatDate = (value?: Date) => {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
};

/** 中文按 400 字/分钟、英文按 180 词/分钟粗估，用于阅读时长。 */
export const readingMinutes = (body = "") => {
  const cjk = (body.match(/[\u4e00-\u9fff]/g) ?? []).length;
  const latin = (body.replace(/[\u4e00-\u9fff]/g, "").match(/[A-Za-z0-9_]+/g) ?? []).length;
  return Math.max(1, Math.round(cjk / 400 + latin / 180));
};
