import json
from pathlib import Path
from src.config.settings import OUTPUT_DIR

class EvidenceGraph:
    def __init__(self, case_id: str):
        self.case_id = case_id
        self.graph_file = OUTPUT_DIR / case_id / "graph.json"
        self.nodes = {}
        self.edges = []
        self.load_graph()

    def load_graph(self):
        if self.graph_file.exists():
            with open(self.graph_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.nodes = {n["entity_id"]: n for n in data.get("nodes", [])}
                self.edges = data.get("edges", [])

    def save_graph(self):
        if not (OUTPUT_DIR / self.case_id).exists():
            return
        with open(self.graph_file, "w", encoding="utf-8") as f:
            json.dump({"nodes": list(self.nodes.values()), "edges": self.edges}, f, indent=4)

    def add_node(self, entity_id: str, entity_type: str, properties: dict):
        self.nodes[entity_id] = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "properties": properties
        }
        self.save_graph()

    def add_edge(self, source_entity: str, target_entity: str, relationship_type: str, source: str, confidence: float, classification: str, evidence_id: str = None):
        if source_entity not in self.nodes or target_entity not in self.nodes:
            raise ValueError("Both source and target nodes must exist in the graph.")
            
        edge = {
            "source_entity": source_entity,
            "target_entity": target_entity,
            "relationship_type": relationship_type,
            "provenance": {
                "source": source,
                "evidence_id": evidence_id,
                "confidence": confidence,
                "classification": classification
            }
        }
        self.edges.append(edge)
        self.save_graph()

    def get_graph(self):
        return {"nodes": list(self.nodes.values()), "edges": self.edges}
