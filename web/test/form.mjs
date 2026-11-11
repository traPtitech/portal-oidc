// Reads the attributes of each <input> in server-rendered HTML.
// html/template writes attribute values with these character references.
const named = { amp: "&", lt: "<", gt: ">", quot: '"' };

function decode(text) {
  return text.replace(/&(#\d+|amp|lt|gt|quot);/g, (_, ref) =>
    ref.startsWith("#")
      ? String.fromCodePoint(Number(ref.slice(1)))
      : named[ref],
  );
}

export function parseInputs(html) {
  return [...html.matchAll(/<input\b([^>]*)>/g)].map(([, attrs]) =>
    Object.fromEntries(
      [...attrs.matchAll(/([\w-]+)(?:="([^"]*)")?/g)].map(([, name, value]) => [
        name,
        decode(value ?? ""),
      ]),
    ),
  );
}

// The fields that a browser sends when it submits the form.
export function formData(inputs) {
  return Object.fromEntries(
    inputs
      .filter((input) => input.name)
      .map((input) => [input.name, input.value ?? ""]),
  );
}
