event_categories = {
    'Authentication': {'4624', '4625', '4798', '4799'},
    'Privilege_Escalation': {'4672', '5379'},
    'Security_Policy_Change': {'5038', '5007', '5340'},
    'Process_Creation': {'1', '5', '4688'},
    'Crash_or_Failure': {'1000', '1002', '6008'}
}

event_categories_weights = {
    'Authentication': {'4624': -0.5, '4625': 1.5, '4798': -0.5, '4799': 1.5},
    'Privilege_Escalation': {'4672': 1.5, '5379': 2.0},
    'Security_Policy_Change': {'5038': 2.0, '5007': 1.5, '5340': 1.5},
    'Process_Creation': {'1': -0.5, '5': -0.5, '4688': 2.0},
    'Crash_or_Failure': {'1000': -0.5, '1002': -0.5, '6008': 2.0}
}


def calculate_uncategorized_event_count(event_ids):
    uncategorized_count = 0
    seen_events = set()
    categorized_events = set()
    for event_id in event_ids:
        if event_id not in seen_events:
            seen_events.add(event_id)
            for category, events in event_categories_weights.items():
                if event_id in events:
                    categorized_events.add(event_id)

    for id in seen_events:
        if id not in categorized_events:
            uncategorized_count += 1
    return uncategorized_count


def extract_event_category_features(event_id):
    features = {}

    for category, events in event_categories.items():

        category_feature = f"{category}"
        features[category_feature] = 0

        if event_id and event_id in events:
            features[category_feature] += 1

    return features
