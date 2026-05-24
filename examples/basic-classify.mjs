import { Firewall, HookLabel } from "@silmaril-security/sdk";

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing ${name}`);
  }
  return value;
}

const fw = new Firewall({
  apiKey: requiredEnv("SILMARIL_API_KEY"),
  apiUrl: requiredEnv("SILMARIL_API_URL"),
});

const result = await fw.classify("What is the capital of France?", {
  hook: HookLabel.USER_INPUT,
  metadata: {
    example: "basic-classify",
  },
});

console.log({
  prediction: result.prediction,
  score: result.score,
  threshold: result.threshold,
});
