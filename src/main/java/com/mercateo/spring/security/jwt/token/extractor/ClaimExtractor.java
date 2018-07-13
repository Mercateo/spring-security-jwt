/**
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt.token.extractor;

import java.lang.reflect.Field;

import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.DoubleNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import io.vavr.Function1;
import io.vavr.Tuple;
import io.vavr.collection.Array;
import io.vavr.collection.HashMap;
import io.vavr.collection.Map;
import io.vavr.collection.Stream;
import lombok.val;

class ClaimExtractor {

    private final Map<Class<?>, Function1<Object, Object>> accessors = HashMap.ofEntries( //
            Tuple.of(TextNode.class, (node) -> ((TextNode) node).asText()), //
            Tuple.of(IntNode.class, (node) -> ((IntNode) node).asInt()), //
            Tuple.of(DoubleNode.class, (node) -> ((DoubleNode) node).asDouble()), //
            Tuple.of(BooleanNode.class, (node) -> ((BooleanNode) node).asBoolean()), //
            Tuple.of(ArrayNode.class, (node) -> extractArray((ArrayNode) node)), //
            Tuple.of(ObjectNode.class, (node) -> extractObject((ObjectNode) node))

    );

    Object extract(Claim claim) {
        final Class<? extends Claim> claimClass = claim.getClass();
        if (claimClass.getSimpleName().equals("JsonNodeClaim")) {
            try {
                final Field data = claimClass.getDeclaredField("data");
                data.setAccessible(true);
                return extractNode(data.get(claim));
            } catch (IllegalAccessException | NoSuchFieldException e) {
                return null;
            }
        }
        return null;
    }

    private Object extractNode(Object rawClaim) {
        val accessorOption = accessors.get(rawClaim.getClass());
        return accessorOption.map(accessor -> accessor.apply(rawClaim)).getOrNull();
    }

    private Object extractArray(ArrayNode node) {
        return create(node.elements()).map(this::extractNode).collect(Array.collector()).toJavaArray();
    }

    private Object extractObject(ObjectNode node) {
        return create(node.fields())
            .groupBy(java.util.Map.Entry::getKey)
            .mapValues(Stream::head)
            .mapValues(java.util.Map.Entry::getValue)
            .mapValues(this::extractNode)
            .toJavaMap();
    }

    private static <T> Stream<T> create(java.util.Iterator<? extends T> iterator) {
        return iterator.hasNext() ? Stream.cons(iterator.next(), () -> create(iterator)) : Stream.Empty.instance();
    }
}
