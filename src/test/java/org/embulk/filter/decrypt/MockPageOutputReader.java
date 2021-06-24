/*
 * Copyright 2018 The Embulk project
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

package org.embulk.filter.decrypt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.embulk.spi.Column;
import org.embulk.spi.Page;
import org.embulk.spi.PageReader;
import org.embulk.spi.Schema;
import org.embulk.spi.TestPageBuilderReader;
import org.embulk.spi.type.Types;

import java.io.IOException;

public class MockPageOutputReader
{
    private static final ObjectReader jsonReader = new ObjectMapper().reader();

    private MockPageOutputReader()
    {
    }

    public static ArrayNode readPageOutput(Schema schema, TestPageBuilderReader.MockPageOutput pageOutput) throws IOException
    {
        ArrayNode nodes = (ArrayNode) jsonReader.createArrayNode();
        for (Page page : pageOutput.pages) {
            nodes.addAll(pageToJsonArray(schema, page));
        }
        return nodes;
    }

    private static ArrayNode pageToJsonArray(Schema schema, Page page) throws IOException
    {
        ArrayNode nodes = (ArrayNode) jsonReader.createArrayNode();
        PageReader reader = new PageReader(schema);
        reader.setPage(page);
        while (reader.nextRecord()) {
            ObjectNode node = (ObjectNode) jsonReader.createObjectNode();
            for (Column column : schema.getColumns()) {
                if (Types.STRING == column.getType()) {
                    if (!reader.isNull(column)) {
                        node.put(column.getName(), reader.getString(column));
                    }
                }
                else if (Types.BOOLEAN == column.getType()) {
                    node.put(column.getName(), reader.getBoolean(column));
                }
                else if (Types.DOUBLE == column.getType()) {
                    node.put(column.getName(), reader.getDouble(column));
                }
                else if (Types.JSON == column.getType()) {
                    if (!reader.isNull(column)) {
                        node.set(column.getName(), jsonReader.readTree(reader.getJson(column).toJson()));
                    }
                }
                else if (Types.LONG == column.getType()) {
                    node.put(column.getName(), reader.getLong(column));
                }
                else if (Types.TIMESTAMP == column.getType()) {
                    if (!reader.isNull(column)) {
                        node.put(column.getName(), reader.getTimestamp(column).toEpochMilli());
                    }
                }
            }
            nodes.add(node);
        }
        return nodes;
    }
}
