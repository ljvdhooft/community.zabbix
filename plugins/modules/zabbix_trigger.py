#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils

class Trigger(ZabbixBase):
    #exist trigger
    def is_trigger_exist(self, trigger_name, host_name):
        host_id = self.get_hostid_by_host_name(host_name)
        result = self._zapi.trigger.get({"selectTags": "extend", "selectDependencies": "true", "expandExpression": "true", "filter": {"description": trigger_name, "hostid": host_id}})
        return result
    
    def get_triggerid_by_trigger_and_hostid(self, trigger_name, host_id):
        return self._zapi.trigger.get({"filter": {"description": trigger_name, "hostid": host_id}})
    
    #check if host exists
    def check_host_exist(self, host_name):
        result = self._zapi.host.get({"filter": {"host": host_name}})
        if not result:
            self._module.fail_json(msg="Host not found %s" % host_name)
        return True

    def get_itemid_by_item_and_hostid(self, item_name, host_id):
        return self._zapi.item.get({"filter": {"name": item_name, "hostid": host_id}})

    def get_hostid_by_host_name(self, host_name):
        host_list = self._zapi.host.get({"output": "extend", "filter": {"host": [host_name]}})
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return int(host_list[0]["hostid"])
        
    def construct_dependencies(self, dependencies):
        i = 0
        for dependency in dependencies:
            trigger_id = self.get_triggerid_by_trigger_and_hostid(dependency["trigger_name"], dependency["host_name"])
            if trigger_id:
                dependencies[i] = trigger_id
            else:
                self._module.fail_json(msg='trigger %s not found on host %s' % (dependency["trigger_name"], dependency["host_name"]))
            i += 1
        return dependencies

    def add_trigger(self, trigger_name, status, expression, event_name, operational_data, description, severity, problem_mode, url, url_name, ok_event_generation, recovery_expression, ok_event_closes, match_tag, manual_close, tags, dependencies, host_id, host_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                parameters = {"description": trigger_name, "expression": expression, "status": status}
                if event_name is not None:
                    parameters["event_name"] = event_name
                if operational_data is not None:
                    parameters["opdata"] = operational_data
                if description is not None:
                    parameters["comments"] = description
                if severity is not None:
                    parameters["priority"] = severity
                if problem_mode is not None:
                    parameters["type"] = problem_mode
                if url is not None:
                    parameters["url"] = url
                if url_name is not None:
                    parameters["url_name"] = url_name
                if ok_event_generation is not None:
                    parameters["recovery_mode"] = ok_event_generation
                if recovery_expression is not None:
                    parameters["recovery_expression"] = recovery_expression
                if ok_event_closes is not None:
                    parameters["correlation_mode"] = ok_event_closes
                if match_tag is not None:
                    parameters["correlation_tag"] = match_tag
                if manual_close is not None:
                    parameters["manual_close"] = manual_close
                if tags is not None:
                    parameters["tags"] = tags
                if dependencies is not None:
                    parameters["dependencies"] = dependencies
                self._zapi.trigger.create(parameters)
        except Exception as e:
            self._module.fail_json(msg="Failed to create trigger %s: %s" % (trigger_name, e))

    def update_trigger(self, trigger_exist, trigger_id, trigger_name, status, expression, event_name, operational_data, description, severity, problem_mode, url, url_name, ok_event_generation, recovery_expression, ok_event_closes, match_tag, manual_close, tags, dependencies, host_id, host_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                parameters = {"triggerid": trigger_id, "status": status}
                if expression is not None:
                    parameters["expression"] = expression
                if event_name is not None:
                    parameters["event_name"] = event_name
                if operational_data is not None:
                    parameters["opdata"] = operational_data
                if description is not None:
                    parameters["comments"] = description
                if severity is not None:
                    parameters["priority"] = severity
                if problem_mode is not None:
                    parameters["type"] = problem_mode
                if url is not None:
                    parameters["url"] = url
                if url_name is not None:
                    parameters["url_name"] = url_name
                if ok_event_generation is not None:
                    parameters["recovery_mode"] = ok_event_generation
                if recovery_expression is not None:
                    parameters["recovery_expression"] = recovery_expression
                if ok_event_closes is not None:
                    parameters["correlation_mode"] = ok_event_closes
                if match_tag is not None:
                    parameters["correlation_tag"] = match_tag
                if manual_close is not None:
                    parameters["manual_close"] = manual_close
                if tags is not None:
                    parameters["tags"] = tags
                if dependencies is not None:
                    parameters["dependencies"] = dependencies
                self._zapi.trigger.update(parameters)
        except Exception as e:
            self._module.fail_json(msg="Failed to update trigger %s: %s" % (trigger_name, e))                

    def delete_trigger(self, trigger_id, trigger_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.trigger.delete([trigger_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete trigger %s: %s" % (trigger_name, e))

    def check_all_properties(self, trigger_exist, trigger_id, trigger_name, status, expression, event_name, operational_data, description, severity, problem_mode, url, url_name, ok_event_generation, recovery_expression, ok_event_closes, match_tag, manual_close, tags, dependencies, host_id, host_name):
        if status and int(status) != int(trigger_exist["status"]):
            return True
        if expression and expression != trigger_exist["expression"]:
            return True
        if event_name and event_name != trigger_exist["event_name"]:
            return True
        if operational_data and operational_data != trigger_exist["opdata"]:
            return True
        if description and description != trigger_exist["comments"]:
            return True
        if severity and int(severity) != int(trigger_exist["priority"]):
            return True
        if problem_mode and int(problem_mode) != int(trigger_exist["type"]):
            return True
        if url and url != trigger_exist["url"]:
            return True
        if url_name and url_name != trigger_exist["url_name"]:
            return True
        if ok_event_generation and int(ok_event_generation) != int(trigger_exist["recovery_mode"]):
            return True
        if recovery_expression and recovery_expression != trigger_exist["recovery_expression"]:
            return True
        if ok_event_closes and int(ok_event_closes) != int(trigger_exist["correlation_mode"]):
            return True
        if match_tag and match_tag != trigger_exist["correlation_tag"]:
            return True
        if manual_close and int(manual_close) != int(trigger_exist["manual_close"]):
            return True
        if tags and tags != trigger_exist["tags"]:
            return True
        if dependencies and dependencies != trigger_exist["dependencies"]:
            return True
        
        return False

def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        trigger_name=dict(type="str", required=True),
        host_name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        status=dict(type="str", choices=["enabled", "disabled"]),
        expression=dict(type="str"),
        event_name=dict(type="str"),
        operational_data=dict(type="str"),
        description=dict(type="str"),
        severity=dict(type="str", choices=["not_classified", "information", "warning", "average", "high", "disaster"]),
        problem_mode=dict(type="str", choices=["single", "multiple"]),
        url=dict(type="str"),
        url_name=dict(type="str"),
        ok_event_generation=dict(type="str", choices=["expression", "recovery_expression", "none"]),
        recovery_expression=dict(type="str"),
        ok_event_closes=dict(type="str", choices=["all_problems", "match_tag_values"]),
        match_tag=dict(type="str", required_if=[["ok_event_closes", 1, ["match_tag_values"]]]),
        manual_close=dict(type="bool",),
        tags=dict(type="list", elements="dict", default=[], options=dict(
            tag=dict(type="str", required=True),
            value=dict(type="str", required=True)
        )),
        dependencies=dict(type="list", elements="dict", options=dict(
            host_name=dict(type="str"),
            trigger_name=dict(type="str", required=True)
        ))
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
        )

    trigger_name = module.params["trigger_name"]
    host_name = module.params["host_name"]
    state = module.params["state"]
    status = module.params["status"]
    expression = module.params["expression"]
    event_name = module.params["event_name"]
    operational_data = module.params["operational_data"]
    description = module.params["description"]
    severity = module.params["severity"]
    problem_mode = module.params["problem_mode"]
    url = module.params["url"]
    url_name = module.params["url_name"]
    ok_event_generation = module.params["ok_event_generation"]
    recovery_expression = module.params["recovery_expression"]
    ok_event_closes = module.params["ok_event_closes"]
    manual_close = module.params["manual_close"]
    tags = module.params["tags"]
    dependencies = module.params["dependencies"]
    match_tag = module.params["match_tag"]

    # convert enabled to 0; disabled to 1
    status = 1 if status == "disabled" else 0

    trigger = Trigger(module)

    # check if trigger exist
    is_trigger_exist = trigger.is_trigger_exist(trigger_name, host_name)

    # find host id
    host_id = ""
    if host_name is not None:
        host_id = trigger.get_hostid_by_host_name(host_name)
        if host_id is None:
            module.fail_json(msg="host %s does not exist." % host_name)
    else:
        module.fail_json(msg="host_name must not be empty.")

    if dependencies:
        dependencies = trigger.construct_dependencies(dependencies)

    # check expression when creating new trigger
    if not is_trigger_exist and not expression:
        module.fail_json(msg='"expression" required when creating a trigger')
    
    # convert bools/choices to integers
    if severity:
        severity_types = {"not_classified": 0, "information": 1, "warning": 2, "average": 3, "high": 4, "disaster": 5}
        if severity in list(severity_types.keys()):
            severity = severity_types[severity]
        else:
            severity = int(severity)
    if problem_mode:
        problem_mode_types = {"single": 0, "multiple": 1}
        if problem_mode in list(problem_mode_types.keys()):
            problem_mode = problem_mode_types[problem_mode]
        else:
            problem_mode = int(problem_mode)
    if ok_event_generation:
        ok_event_generation_types = {"expression": 0, "recovery_expression": 1, "none": 2}
        if ok_event_generation in list(ok_event_generation_types.keys()):
            ok_event_generation = ok_event_generation_types[ok_event_generation]
        else:
            ok_event_generation = int(ok_event_generation)
    if ok_event_closes:
        ok_event_closes_types = {"all_problems": 0, "match_tag_values": 1}
        if ok_event_closes in list(ok_event_closes_types.keys()):
            ok_event_closes = ok_event_closes_types[ok_event_closes]
        else:
            ok_event_closes = int(ok_event_closes)
    if manual_close:
        manual_close = 0 if manual_close == False else 1
    
    # conditional parameter filtering
    if ok_event_generation == 1:
        if not recovery_expression:
            module.fail_json(msg='"recovery_expression" required when "ok_event_generation" is set to "recovery_expression"')

    if ok_event_closes == 1:
        if not match_tag:
            module.fail_json(msg='"match_tag" required when "ok_event_closes" is set to "match_tag_values"')

    if is_trigger_exist:
        trigger_id = is_trigger_exist[0]["triggerid"]
    
        if state == "absent":
            # remove trigger
            trigger.delete_trigger(trigger_id, trigger_name)
        else:
            # update trigger if something has changed
            if trigger.check_all_properties(is_trigger_exist[0], trigger_id, trigger_name, status, expression, event_name, operational_data, description, severity, problem_mode, url, url_name, ok_event_generation, recovery_expression, ok_event_closes, match_tag, manual_close, tags, dependencies, host_id, host_name):
                # update the trigger
                trigger.update_trigger(is_trigger_exist[0], trigger_id, trigger_name, status, expression, event_name, operational_data, description, severity, problem_mode, url, url_name, ok_event_generation, recovery_expression, ok_event_closes, match_tag, manual_close, tags, dependencies, host_id, host_name)

                module.exit_json(changed=True, result="Successfully updated trigger %s on host %s" % (trigger_name, host_name))
            else:
                module.exit_json(changed=False)
    else:
        if state == "absent":
            # trigger is already deleted
            module.exit_json(changed=False)
        if not host_id:
            module.fail_json(msg='Specify a host when creating trigger "%s"' % trigger_name)

        # create trigger
        trigger_id = trigger.add_trigger(trigger_name, status, expression, event_name, operational_data, description, severity, problem_mode, url, url_name, ok_event_generation, recovery_expression, ok_event_closes, match_tag, manual_close, tags, dependencies, host_id, host_name)

        module.exit_json(changed=True, result="Successfully added trigger %s on host %s" % (trigger_name, host_name))

if __name__ == "__main__":
    main()