/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Represents a valid_policy_tree node (leaf) as per RFC 5280
 *
 */
public class PolicyTreeNode {

    /** Represents an anyPolicy OID */
    private static final String ANY_POLICY = "2.5.29.32.0";

    /** Represents a valid_policy element of a policy tree node */
    private final String validPolicy;

    /** Represents a qualifier_set element of a policy tree node */
    private final Set<String> qualifierSet;

    /** Represents a expected_policy_set element of a policy tree node */
    private final Set<String> expectedPolicySet;

    /** Represents policy node's children */
    private final Set<PolicyTreeNode> children = new HashSet<>();

    /**
     * Default constructor
     *
     * @param policyOid {@link String} OID of the policy
     * @param policyQualifier {@link String} qualifier URL of the policy
     */
    public PolicyTreeNode(String policyOid, String policyQualifier) {
        this.validPolicy = policyOid;
        this.qualifierSet = policyQualifier != null ? Collections.singleton(policyQualifier) : Collections.emptySet();
        this.expectedPolicySet = Collections.singleton(policyOid);
    }

    /**
     * Initialize the first node of the valid policy tree (containing anyPolicy as the first element)
     *
     * @return {@link PolicyTreeNode}
     */
    public static PolicyTreeNode initTree() {
        return new PolicyTreeNode(ANY_POLICY, null);
    }

    /**
     * Returns if the current policy node represents anyPolicy
     *
     * @return TRUE if the policy node represents anyPolicy, FALSE otherwise
     */
    public boolean isAnyPolicy() {
        return ANY_POLICY.equals(validPolicy);
    }

    /**
     * This method adds a {@code policyNode} to the node's children, when applicable
     *
     * @param policyNode {@link PolicyTreeNode} to add if applicable
     * @return whether the node has been added
     */
    public boolean addChildNodeIfMatch(PolicyTreeNode policyNode) {
        /*
         * (i) For each node of depth i-1 in the valid_policy_tree
         * where P-OID is in the expected_policy_set, create a
         * child node as follows: set the valid_policy to P-OID,
         * set the qualifier_set to P-Q, and set the
         * expected_policy_set to {P-OID}.
         */
        if (this.expectedPolicySet.contains(policyNode.validPolicy)) {
            children.add(policyNode);
            return true;
        }
        /*
         * (ii)  If there was no match in step (i) and the
         * valid_policy_tree includes a node of depth i-1 with
         * the valid_policy anyPolicy, generate a child node with
         * the following values: set the valid_policy to P-OID,
         * set the qualifier_set to P-Q, and set the
         * expected_policy_set to {P-OID}.
         */
        else if (isAnyPolicy()) {
            // AnyPolicy child is created within the caller class
            children.add(policyNode);
            return true;
        }
        return false;
    }

    /**
     * Creates any policy children corresponding to the current policy node
     *
     * @return set of {@link PolicyTreeNode}s
     */
    public Set<PolicyTreeNode> createAnyPolicyChildren() {
        Set<PolicyTreeNode> anyPolicyChildren = new HashSet<>();
        for (String expectedPolicy : this.expectedPolicySet) {
            PolicyTreeNode child = new PolicyTreeNode(expectedPolicy, ANY_POLICY);
            anyPolicyChildren.add(child);
        }
        this.children.addAll(anyPolicyChildren);
        return anyPolicyChildren;
    }

    /**
     * Removes nodes at the given {@code depthLevel} if not having children nodes
     *
     * @param depthLevel the level to remove nodes without children from (0 is considered as the current node)
     * @return {@link PolicyTreeNode}
     */
    public PolicyTreeNode deleteNodesAtLevelWithoutChildren(int depthLevel) {
        if (depthLevel > 0) {
            Iterator<PolicyTreeNode> iterator = children.iterator();
            while (iterator.hasNext()) {
                PolicyTreeNode child = iterator.next();
                if (child.deleteNodesAtLevelWithoutChildren(depthLevel - 1) == null) {
                    iterator.remove();
                }
            }
        }
        return Utils.isCollectionEmpty(children) ? null : this;
    }

}
