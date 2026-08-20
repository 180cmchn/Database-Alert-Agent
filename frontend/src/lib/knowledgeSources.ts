const EXTERNAL_KNOWLEDGE_SOURCE = "external_knowledge";

export function knowledgeSourcesForSave(
  configuredSources: string[],
  externalKnowledgeSelected: boolean,
): string[] {
  const preserved = configuredSources.filter(
    (source) => source !== EXTERNAL_KNOWLEDGE_SOURCE,
  );
  if (!externalKnowledgeSelected) return preserved;

  const externalIndex = configuredSources.indexOf(EXTERNAL_KNOWLEDGE_SOURCE);
  if (externalIndex < 0) return [...preserved, EXTERNAL_KNOWLEDGE_SOURCE];
  return configuredSources.filter(
    (source, index) => source !== EXTERNAL_KNOWLEDGE_SOURCE || index === externalIndex,
  );
}
