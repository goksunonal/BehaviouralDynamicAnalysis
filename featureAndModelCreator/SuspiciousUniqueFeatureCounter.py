suspicious_fields = ['PolicyDownloadTimeElapsedInMilliseconds', 'Event_UserData_LogFileCleared_Channel',
                     'DesiredAccess', 'FileNameBuffer', 'ImagePath', 'MessageNumber',
                     'MessageTotal', 'ScriptBlockText', 'param1', 'param4']


def calculate_unique_suspicious_features(event):
    unique_suspicious = set()

    for field in suspicious_fields:
        value = event.get(field)
        if value:
            unique_suspicious.add(field)

    return unique_suspicious
