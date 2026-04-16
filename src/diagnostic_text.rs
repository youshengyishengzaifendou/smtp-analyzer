use std::borrow::Cow;

use crate::model::Diagnostic;

pub fn label(kind: &str) -> Cow<'_, str> {
    match kind {
        "vlan_asymmetry" => Cow::Borrowed("疑似 VLAN 不对称"),
        _ if !kind.is_empty() => Cow::Borrowed(kind),
        _ => Cow::Borrowed("存在异常"),
    }
}

pub fn format_summary(
    label: &str,
    flow_indices: &[usize],
    fallback_summary: Option<&str>,
) -> String {
    if flow_indices.is_empty() {
        fallback_summary
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| label.to_string())
    } else {
        format!("第{}个流：{}", format_flow_ranges(flow_indices), label)
    }
}

pub fn format_note(label: &str, flow_index: usize) -> String {
    format!("第{}个流：{}", flow_index, label)
}

pub fn format_flow_ranges(flow_indices: &[usize]) -> String {
    if flow_indices.is_empty() {
        return String::new();
    }

    let mut normalized = flow_indices.to_vec();
    normalized.sort_unstable();
    normalized.dedup();

    let mut ranges = Vec::new();
    let mut start = normalized[0];
    let mut end = normalized[0];

    for &value in normalized.iter().skip(1) {
        if value == end + 1 {
            end = value;
        } else {
            ranges.push(format_single_range(start, end));
            start = value;
            end = value;
        }
    }

    ranges.push(format_single_range(start, end));
    ranges.join("、")
}

pub fn group_summaries(diagnostics: &[Diagnostic]) -> Vec<String> {
    let mut grouped: Vec<(String, Vec<usize>, String)> = Vec::new();

    for diagnostic in diagnostics {
        let summary_label = label(&diagnostic.kind).into_owned();
        if let Some(existing) = grouped.iter_mut().find(|item| item.0 == summary_label) {
            existing.1.extend_from_slice(&diagnostic.flow_indices);
            if existing.2.is_empty() {
                existing.2 = diagnostic.summary.clone();
            }
        } else {
            grouped.push((
                summary_label,
                diagnostic.flow_indices.clone(),
                diagnostic.summary.clone(),
            ));
        }
    }

    let mut result = grouped
        .into_iter()
        .map(|(summary_label, flow_indices, fallback_summary)| {
            let first_index = flow_indices.iter().copied().min().unwrap_or(usize::MAX);
            let summary = format_summary(&summary_label, &flow_indices, Some(&fallback_summary));
            (first_index, summary)
        })
        .collect::<Vec<_>>();

    result.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    result.into_iter().map(|(_, summary)| summary).collect()
}

fn format_single_range(start: usize, end: usize) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

#[cfg(test)]
mod tests {
    use super::{format_flow_ranges, format_note, format_summary, group_summaries, label};
    use crate::model::Diagnostic;

    #[test]
    fn format_summary_uses_ranges_for_multiple_flows() {
        assert_eq!(
            format_summary(&label("vlan_asymmetry"), &[1, 2, 4], None),
            "第1-2、4个流：疑似 VLAN 不对称"
        );
    }

    #[test]
    fn format_note_uses_single_flow_index() {
        assert_eq!(
            format_note(&label("vlan_asymmetry"), 3),
            "第3个流：疑似 VLAN 不对称"
        );
    }

    #[test]
    fn group_summaries_merges_same_kind() {
        let diagnostics = vec![
            Diagnostic {
                kind: "vlan_asymmetry".to_string(),
                flow_indices: vec![2],
                summary: String::new(),
                src_ip: "10.0.0.1".to_string(),
                src_port: 1,
                dst_ip: "10.0.0.2".to_string(),
                dst_port: 2,
                observed_vlans: vec![],
                evidence: vec![],
            },
            Diagnostic {
                kind: "vlan_asymmetry".to_string(),
                flow_indices: vec![1],
                summary: String::new(),
                src_ip: "10.0.0.3".to_string(),
                src_port: 3,
                dst_ip: "10.0.0.4".to_string(),
                dst_port: 4,
                observed_vlans: vec![],
                evidence: vec![],
            },
        ];

        assert_eq!(
            group_summaries(&diagnostics),
            vec!["第1-2个流：疑似 VLAN 不对称".to_string()]
        );
        assert_eq!(format_flow_ranges(&[3, 1, 2, 2]), "1-3");
    }
}
