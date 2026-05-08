"""Improved RADAC = paper-faithful implementation.

Based on:
  Lee, Vanickis, Rogelio, Jacob (2017),
  "Situational Awareness based Risk-Adaptable Access Control in
   Enterprise Networks".

Components (matching Figure 2 of the paper):
  * fuzzy_engine.py    - FURZE Risk Evaluation Function (Mamdani inference)
  * fcm.py             - Rule-Based Fuzzy Cognitive Map (Carvalho & Tome 1999)
  * mission_graph.py   - Mission Dependency Graph (Holspopple, Watters)
  * ssa_evaluator.py   - SSA evaluator: MDG + RB-FCM -> risk modifier
  * model.py           - ImprovedRADACModel: glues fuzzy core + SSA + decision
"""
