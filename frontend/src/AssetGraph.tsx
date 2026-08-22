import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

interface GraphNode {
  id: string;
  type: string;
  label: string;
  data: Record<string, unknown>;
}

interface GraphEdge {
  source: string;
  target: string;
  type: string;
}

interface AssetGraphData {
  asset_id: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface AssetGraphProps {
  data: AssetGraphData | null;
  width?: number;
  height?: number;
}

const NODE_COLORS: Record<string, string> = {
  asset: '#2563eb',
  domain: '#7c3aed',
  subdomain: '#059669',
  port: '#dc2626',
  ssl: '#ea580c',
  finding: '#db2777',
};

const NODE_RADIUS: Record<string, number> = {
  asset: 20,
  domain: 16,
  subdomain: 14,
  port: 12,
  ssl: 12,
  finding: 10,
};

export const AssetGraph: React.FC<AssetGraphProps> = ({ data, width = 800, height = 600 }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const { nodes, edges } = data;

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id((d: GraphNode) => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius((d: GraphNode) => NODE_RADIUS[d.type] + 5))
      .force('x', d3.forceX(width / 2).strength(0.05))
      .force('y', d3.forceY(height / 2).strength(0.05));

    const link = svg.append('g')
      .attr('stroke', '#9ca3af')
      .attr('stroke-opacity', 0.6)
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke-width', 1.5);

    const node = svg.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .call(drag(simulation));

    node.append('circle')
      .attr('r', (d: GraphNode) => NODE_RADIUS[d.type])
      .attr('fill', (d: GraphNode) => NODE_COLORS[d.type] || '#6b7280')
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);

    node.append('text')
      .attr('dy', (d: GraphNode) => NODE_RADIUS[d.type] + 14)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('fill', '#374151')
      .text((d: GraphNode) => d.label)
      .style('pointer-events', 'none');

    node.append('title')
      .text((d: GraphNode) => {
        const data = d.data as Record<string, unknown>;
        return Object.entries(data)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');
      });

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node
        .attr('transform', (d: GraphNode) => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [data, width, height]);

  function drag(simulation: d3.Simulation<GraphNode, GraphEdge>) {
    function dragstarted(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event: d3.D3DragEvent<SVGGElement, GraphNode, GraphNode>) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return d3.drag<SVGGElement, GraphNode>()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended);
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-96 text-gray-500">
        No graph data available
      </div>
    );
  }

  return (
    <div className="relative">
      <svg
        ref={svgRef}
        width={width}
        height={height}
        style={{ background: '#f9fafb', borderRadius: '8px' }}
      />
      <div className="mt-4 flex flex-wrap gap-4 text-sm">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <span key={type} className="flex items-center gap-1">
            <span
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: color }}
            />
            {type.charAt(0).toUpperCase() + type.slice(1)}
          </span>
        ))}
      </div>
    </div>
  );
};

export default AssetGraph;